import asyncio
import aiohttp
import asyncpg
import os
import re
import time
import logging
from datetime import datetime, timedelta
from tenacity import retry, wait_exponential, stop_after_attempt
from celery import Celery, chord
from flask import Flask

# --- Configuration Management ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
DB_DSN = os.environ.get("DATABASE_URL") or (
    f"postgresql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}"
    f"@{os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT', '5432')}/{os.environ.get('DB_NAME')}"
)
BROKER_URL = os.environ.get("BROKER_URL", "redis://localhost:6379/0")
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
# Increase MAX_PAGES as needed to extract more keys.
MAX_PAGES = int(os.environ.get("MAX_PAGES", "5"))
# Use an hourly window; configure via environment variable.
WINDOW_HOURS = int(os.environ.get("WINDOW_HOURS", "1"))
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

    # Determine the time window for scanning.
    last_scanned = await get_last_scanned(pool)
    if last_scanned:
        start_time = last_scanned
    else:
        # If no previous scan, start from a default time (e.g., 30 days ago).
        start_time = datetime.utcnow() - timedelta(days=30)
    end_time = datetime.utcnow()

    current_time = start_time
    total_unique = 0

    # Iterate over time windows (using an hourly window).
    while current_time < end_time:
        window_end = min(current_time + timedelta(hours=WINDOW_HOURS), end_time)
        # Use GitHub's pushed range syntax.
        time_filter = f" pushed:{current_time.isoformat()}..{window_end.isoformat()}"
        logger.info(f"Scanning window: {current_time.isoformat()} to {window_end.isoformat()}")

        results = []
        for page in range(1, MAX_PAGES + 1):
            query = search_term + time_filter
            url = f"https://api.github.com/search/code?q={query}&per_page=1000&page={page}"
            try:
                data = await fetch_github(url)
                items = data.get("items", [])
                if not items:
                    break
                results.extend(items)
            except Exception as e:
                logger.error(f"Error fetching GitHub items for pattern {pattern_name} in window {time_filter}: {e}")
                break
            await asyncio.sleep(2)
        
        # Process the results from this time window.
        tasks = [process_item(item, pool) for item in results]
        counts = await asyncio.gather(*tasks, return_exceptions=True)
        for count in counts:
            if isinstance(count, Exception):
                logger.error(f"Error in processing task: {count}")
            else:
                total_unique += count

        current_time = window_end

    logger.info(f"Scan complete for {pattern_name}. Total unique keys saved: {total_unique}")
    await update_last_scanned(pool, datetime.utcnow())
    await pool.close()

async def process_item(item, pool):
    repo_url = item["repository"]["html_url"]
    file_path = item["path"]
    logger.info(f"Processing file: {repo_url}/{file_path}")
    download_url = item.get("download_url")
    file_url = download_ur
