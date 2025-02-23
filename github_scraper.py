import asyncio
import aiohttp
import asyncpg
import os
import re
import logging
from datetime import datetime, timedelta
from tenacity import retry, wait_exponential, stop_after_attempt
from celery import Celery, chord
from celery.signals import worker_process_init
from flask import Flask

# --- Configuration Management ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
DB_DSN = os.environ.get("DATABASE_URL") or (
    f"postgresql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}"
    f"@{os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT', '5432')}/{os.environ.get('DB_NAME')}"
)
BROKER_URL = os.environ.get("BROKER_URL", "redis://localhost:6379/0")
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
PER_PAGE = int(os.environ.get("PER_PAGE", "200"))
MAX_PAGES = int(os.environ.get("MAX_PAGES", "5"))
# Use a smaller window in minutes; you can adjust this (e.g., 15 minutes)
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "15"))
DEFAULT_DAYS = int(os.environ.get("DEFAULT_DAYS", "30"))
# Minimum window size (in minutes) below which we won't subdivide further.
MIN_WINDOW_MINUTES = int(os.environ.get("MIN_WINDOW_MINUTES", "1"))
# --- End Configuration ---

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)
# --- End Logging Setup ---

# --- Celery Setup ---
CELERY_RESULT_BACKEND = BROKER_URL
celery = Celery("scan_tasks", broker=BROKER_URL, backend=CELERY_RESULT_BACKEND)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
# --- End Celery Setup ---

# --- Global Connection Pool ---
global_pool = None

@worker_process_init.connect
def init_worker(**kwargs):
    global global_pool
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    global_pool = loop.run_until_complete(asyncpg.create_pool(dsn=DB_DSN))
    loop.run_until_complete(setup_db(global_pool))
    logger.info("Worker process initialized and connection pool created.")

# --- Flask App ---
def create_flask_app():
    app = Flask(__name__)
    @app.route("/", methods=["GET"])
    def index():
        dispatch_all_scans.delay()
        return "Dispatched scan tasks. Check logs for output.\n"
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

# --- Custom Exception ---
class GitHubLimitExceeded(Exception):
    pass

# --- HTTP Helpers ---
@retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(5))
async def fetch_github(url):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as response:
            if response.status == 422:
                text = await response.text()
                if "Cannot access beyond the first 1000 results" in text:
                    logger.warning("GitHub API error 422: Cannot access beyond the first 1000 results.")
                    raise GitHubLimitExceeded(text)
                else:
                    raise Exception(f"GitHub API error {response.status}: {text}")
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

# --- Recursive Scan Function ---
async def scan_window(pattern_name, window_start, window_end):
    """Scan a time window for the given pattern, paginating through results.
       If GitHubLimitExceeded is raised, subdivide the window and aggregate."""
    total = 0
    for page in range(1, MAX_PAGES + 1):
        query = f"{PATTERN_SEARCH_TERMS[pattern_name]} pushed:{window_start.isoformat()}..{window_end.isoformat()}"
        url = f"https://api.github.com/search/code?q={query}&per_page={PER_PAGE}&page={page}"
        try:
            data = await fetch_github(url)
        except GitHubLimitExceeded as gle:
            # Subdivide the window if possible.
            duration = window_end - window_start
            if duration >= timedelta(minutes=MIN_WINDOW_MINUTES * 2):
                mid = window_start + duration / 2
                logger.info(f"Subdividing window for {pattern_name}: {window_start.isoformat()} to {window_end.isoformat()}")
                left = await scan_window(pattern_name, window_start, mid)
                right = await scan_window(pattern_name, mid, window_end)
                return left + right
            else:
                logger.warning(f"Window too small to subdivide further for {pattern_name}: {window_start.isoformat()} to {window_end.isoformat()}")
                return 0
        items = data.get("items", [])
        if not items:
            break  # no more results for this page
        tasks = [process_item(item, global_pool) for item in items]
        counts = await asyncio.gather(*tasks, return_exceptions=True)
        total += sum(count for count in counts if not isinstance(count, Exception))
    return total

# --- Celery Task for a Single Window ---
@celery.task(name="celery_scan_window")
def celery_scan_window(pattern_name, window_start_str, window_end_str):
    window_start = datetime.fromisoformat(window_start_str)
    window_end = datetime.fromisoformat(window_end_str)
    try:
        result = asyncio.run(scan_window(pattern_name, window_start, window_end))
        return result
    except Exception as e:
        raise Exception(f"celery_scan_window failed for pattern {pattern_name} window {window_start_str} to {window_end_str}: {str(e)}")

# --- Task to Process an Individual File ---
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
# --- End File Processing ---

# --- Dispatching Tasks in Batches (Window Chain) ---
@celery.task(name="dispatch_window")
def dispatch_window(_, pattern_name, window_start_str, window_end_str, now_str):
    """
    Callback for a window batch.
    If the current window_end is before 'now', schedule the next window.
    """
    window_end = datetime.fromisoformat(window_end_str)
    now = datetime.fromisoformat(now_str)
    logger.info(f"Completed window for {pattern_name}: {window_start_str} to {window_end_str}")
    if window_end < now:
        next_start = window_end
        next_end = min(next_start + timedelta(minutes=WINDOW_MINUTES), now)
        # Schedule the next window for this pattern.
        tasks = [celery_scan_window.s(pattern_name, next_start.isoformat(), next_end.isoformat())]
        chord(tasks)(dispatch_window.s(pattern_name, next_start.isoformat(), next_end.isoformat(), now_str))
    else:
        logger.info(f"All windows complete for pattern: {pattern_name}")

@celery.task(name="dispatch_all_scans")
def dispatch_all_scans():
    now = datetime.utcnow()
    now_str = now.isoformat()
    for pattern_name in PATTERN_SEARCH_TERMS.keys():
        start_time = now - timedelta(days=DEFAULT_DAYS)
        window_end = min(start_time + timedelta(minutes=WINDOW_MINUTES), now)
        tasks = [celery_scan_window.s(pattern_name, start_time.isoformat(), window_end.isoformat())]
        chord(tasks)(dispatch_window.s(pattern_name, start_time.isoformat(), window_end.isoformat(), now_str))
# --- End Task Dispatching ---

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
