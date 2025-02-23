import asyncio
import aiohttp
import asyncpg
import os
import re
import time
import logging
from datetime import datetime
from tenacity import retry, wait_exponential, stop_after_attempt
from celery import Celery
from flask import Flask

# --- Configuration Management ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
DB_DSN = os.environ.get("DATABASE_URL") or (
    f"postgresql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}"
    f"@{os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT', '5432')}/{os.environ.get('DB_NAME')}"
)
BROKER_URL = os.environ.get("BROKER_URL", "redis://localhost:6379/0")
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
MAX_PAGES = int(os.environ.get("MAX_PAGES", "5"))
# --- End Configuration ---

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)
# --- End Logging Setup ---

# --- Celery Setup ---
CELERY_RESULT_BACKEND = BROKER_URL  # using Redis as the backend
celery = Celery("scan_tasks", broker=BROKER_URL, backend=CELERY_RESULT_BACKEND)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
# --- End Celery Setup ---

def create_flask_app():
    """Factory function to create and configure the Flask app."""
    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    def index():
        # Dispatch scan tasks for each API pattern
        dispatch_all_scans.delay()
        return "Dispatched individual scan tasks. Check logs for output.\n"

    return app

flask_app = create_flask_app()

# --- API Patterns and Search Terms ---
# Mapping API pattern names to their GitHub search term.
PATTERN_SEARCH_TERMS = {
    "OpenAI": "OPEN_API_KEY=sk-",
    "AWS": "AKIA",
    "Google API": "AIza",
    "Stripe": "sk_live_",
    "Slack": "xoxb",
    "GitHub Token": "ghp_",
}

API_PATTERNS = {
    "OpenAI": r"OPEN_API_KEY=sk-[a-zA-Z0-9]{48}",
    "AWS": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
}
COMPILED_PATTERNS = {k: re.compile(v) for k, v in API_PATTERNS.items()}
# --- End API Patterns ---

# --- Database Table Setup Functions ---
async def setup_db(pool):
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS leaked_keys (
                id SERIAL PRIMARY KEY,
                repo_url TEXT NOT NULL,
                file_path TEXT NOT NULL,
                key_type TEXT NOT NULL,
                leaked_key TEXT NOT NULL,
                detected_at TIMESTAMP DEFAULT NOW(),
                notified BOOLEAN DEFAULT FALSE
            );
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                id SERIAL PRIMARY KEY,
                last_scanned TIMESTAMP
            );
        """)
    logger.info("Database setup complete.")

async def get_last_scanned(pool):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT last_scanned FROM scan_cache ORDER BY id DESC LIMIT 1;")
        return row["last_scanned"] if row else None

async def update_last_scanned(pool, timestamp):
    async with pool.acquire() as conn:
        await conn.execute("INSERT INTO scan_cache (last_scanned) VALUES ($1);", timestamp)
# --- End DB Setup Functions ---

# --- HTTP Helpers with Retry & Rate Limit Handling ---
@retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(5))
async def fetch_github(url):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as response:
            if response.status == 403:
                logger.warning("Rate limited by GitHub, sleeping for 60 seconds...")
                await asyncio.sleep(60)
                raise Exception("Rate limited")
            if response.status != 200:
                text = await response.text()
                raise Exception(f"GitHub API error {response.status}: {text}")
            return await response.json()

@retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(5))
async def fetch_file_content(url):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as response:
            if response.status == 403:
                logger.warning("Rate limited when fetching file, sleeping for 60 seconds...")
                await asyncio.sleep(60)
                raise Exception("Rate limited on file fetch")
            if response.status != 200:
                raise Exception(f"Error fetching file content {response.status}")
            return await response.text()
# --- End HTTP Helpers ---

# --- GitHub Search & Processing for a Single Pattern ---
async def run_scan_for_pattern(pattern_name):
    search_term = PATTERN_SEARCH_TERMS.get(pattern_name)
    if not search_term:
        logger.error(f"No search term defined for pattern: {pattern_name}")
        return

    logger.info(f"Starting async scan for pattern: {pattern_name} ({search_term})")
    pool = await asyncpg.create_pool(dsn=DB_DSN)
    await setup_db(pool)

    last_scanned = await get_last_scanned(pool)
    filter_str = f" pushed:>{last_scanned.isoformat()}" if last_scanned else ""
    results = []
    for page in range(1, MAX_PAGES + 1):
        query = search_term + filter_str
        url = f"https://api.github.com/search/code?q={query}&per_page=100&page={page}"
        try:
            data = await fetch_github(url)
            items = data.get("items", [])
            if not items:
                break
            results.extend(items)
        except Exception as e:
            logger.error(f"Error fetching GitHub items for pattern {pattern_name}: {e}")
            break
        await asyncio.sleep(2)
    
    total_unique = 0
    tasks = [process_item(item, pool) for item in results]
    counts = await asyncio.gather(*tasks, return_exceptions=True)
    for count in counts:
        if isinstance(count, Exception):
            logger.error(f"Error in processing task: {count}")
        else:
            total_unique += count
    logger.info(f"Scan complete for {pattern_name}. Total unique keys saved: {total_unique}")
    await update_last_scanned(pool, datetime.utcnow())
    await pool.close()

async def process_item(item, pool):
    repo_url = item["repository"]["html_url"]
    file_path = item["path"]
    logger.info(f"Processing file: {repo_url}/{file_path}")
    download_url = item.get("download_url")
    file_url = download_url if download_url else item.get("html_url")
    if not file_url:
        logger.info(f"No file URL for {repo_url}/{file_path}")
        return 0
    try:
        content = await fetch_file_content(file_url)
    except Exception as e:
        logger.error(f"Error fetching file {file_url}: {e}")
        return 0
    leaked_keys = []
    for key_type, compiled in COMPILED_PATTERNS.items():
        matches = compiled.findall(content)
        for match in matches:
            leaked_keys.append((key_type, match))
    if not leaked_keys:
        logger.info(f"No keys found in {file_url}")
        return 0
    unique_count = 0
    async with pool.acquire() as conn:
        for key_type, leaked_key in leaked_keys:
            row = await conn.fetchrow(
                "SELECT id FROM leaked_keys WHERE repo_url=$1 AND file_path=$2 AND leaked_key=$3",
                repo_url, file_path, leaked_key
            )
            if row:
                logger.info(f"Key already exists for {repo_url}/{file_path}")
                continue
            row = await conn.fetchrow(
                "INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key) VALUES ($1, $2, $3, $4) RETURNING id",
                repo_url, file_path, key_type, leaked_key
            )
            unique_count += 1
            logger.info(f"Unique key: {leaked_key[:10]}... | Inserted ID: {row['id']}")
    return unique_count
# --- End GitHub Search & Processing ---

# --- Celery Tasks ---

# Task to scan a single API pattern.
@celery.task(name="celery_run_scan_for_pattern")
def celery_run_scan_for_pattern(pattern_name):
    asyncio.run(run_scan_for_pattern(pattern_name))

# Master task to dispatch scan tasks for all patterns.
@celery.task(name="dispatch_all_scans")
def dispatch_all_scans():
    for pattern_name in PATTERN_SEARCH_TERMS.keys():
        # Route each task to its dedicated queue.
        queue_name = f"scan_{pattern_name.lower().replace(' ', '_')}"
        celery_run_scan_for_pattern.apply_async(args=[pattern_name], queue=queue_name)
# --- End Celery Tasks ---

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
