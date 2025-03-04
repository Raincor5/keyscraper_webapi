import asyncio
import aiohttp
import asyncpg
import os
import re
import logging
from datetime import datetime, timedelta, timezone
from tenacity import retry, wait_exponential, stop_after_attempt
from celery import Celery, chain, chord
from celery.signals import worker_process_init, worker_process_shutdown
from flask import Flask
from aiolimiter import AsyncLimiter

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
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "15"))
DEFAULT_DAYS = int(os.environ.get("DEFAULT_DAYS", "30"))
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
# Note: We route scanning tasks and scheduling tasks to one set of queues,
# and database-storage tasks to a different queue.
CELERY_RESULT_BACKEND = BROKER_URL
celery = Celery("scan_tasks", broker=BROKER_URL, backend=CELERY_RESULT_BACKEND)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_routes={
        'celery_scan_window': {'queue': 'github_scan'},
        'store_matches': {'queue': 'db_store'},
        'dispatch_window': {'queue': 'window_dispatch'},
        'dispatch_all_scans': {'queue': 'dispatcher'},
    },
)
# --- End Celery Setup ---

# --- Global Variables for DB Pool and Event Loop ---
global_pool = None
worker_loop = None

@worker_process_init.connect
def init_worker(**kwargs):
    global global_pool, worker_loop
    # Create and set a dedicated event loop for this worker process
    worker_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(worker_loop)
    global_pool = worker_loop.run_until_complete(
        asyncpg.create_pool(
            dsn=DB_DSN,
            min_size=1,
            max_size=10,
            max_inactive_connection_lifetime=300
        )
    )
    worker_loop.run_until_complete(setup_db(global_pool))
    logger.info("Worker process initialized and connection pool created.")

@worker_process_shutdown.connect
def shutdown_worker(**kwargs):
    global global_pool, worker_loop
    if global_pool:
        worker_loop.run_until_complete(global_pool.close())
        logger.info("Connection pool closed.")

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

# --- Rate Limiter ---
github_limiter = AsyncLimiter(10, 60)  # 10 requests per minute
# --- End Rate Limiter ---

# --- HTTP Helpers ---
@retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(5))
async def fetch_github(url):
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    async with github_limiter:
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
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        sleep_time = int(retry_after)
                    else:
                        reset_time = response.headers.get("X-RateLimit-Reset")
                        sleep_time = max(int(reset_time) - int(datetime.utcnow().timestamp()), 60) if reset_time else 60
                    logger.warning(f"Rate limited by GitHub, sleeping for {sleep_time} seconds...")
                    await asyncio.sleep(sleep_time)
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

# --- Worker Stage 1: Scanning and Finding Matches ---
# Instead of processing items to immediately write to DB, we extract match info.

def simple_match(content, prefix, expected_length, valid_chars):
    """
    Scan the content for substrings starting with `prefix` that are `expected_length` long,
    and validate that all characters after the prefix are in valid_chars.
    """
    matches = []
    start = 0
    while True:
        index = content.find(prefix, start)
        if index == -1:
            break
        candidate = content[index:index + expected_length]
        # Check if we have a full-length candidate.
        if len(candidate) == expected_length:
            # Validate characters after the prefix.
            if all(c in valid_chars for c in candidate[len(prefix):]):
                matches.append(candidate)
        start = index + 1
    return matches


# Define matching parameters for each key type.
# (prefix, expected_length, allowed characters for the part after the prefix)
MATCHING_PARAMS = {
    "AWS": ("AKIA", 20, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    "GitHub Token": ("ghp_", 40, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    "Google API": ("AIza", 39, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"),
    # Adjust these as needed for other types.
}

async def find_matches(item):
    repo_url = item["repository"]["html_url"]
    file_path = item["path"]
    logger.info(f"Scanning file: {repo_url}/{file_path}")
    download_url = item.get("download_url")
    file_url = download_url if download_url else item.get("html_url")
    if not file_url:
        logger.info(f"No file URL for {repo_url}/{file_path}")
        return []
    try:
        content = await fetch_file_content(file_url)
    except Exception as e:
        logger.error(f"Error fetching file {file_url}: {e}")
        return []
    
    matches_found = []
    # Loop over each key type's parameters.
    for key_type, (prefix, expected_length, valid_chars) in MATCHING_PARAMS.items():
        found = simple_match(content, prefix, expected_length, valid_chars)
        for candidate in found:
            partial = candidate if len(candidate) <= 20 else candidate[:20] + "..."
            logger.info(f"Found {key_type} match in {repo_url}/{file_path}: {partial}")
            matches_found.append({
                "repo_url": repo_url,
                "file_path": file_path,
                "key_type": key_type,
                "leaked_key": candidate,
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
    if not matches_found:
        logger.info(f"No keys found in {file_url}")
    return matches_found


# Modified scan_window returns a list of match dictionaries.
async def scan_window(pattern_name, window_start, window_end):
    all_matches = []
    for page in range(1, MAX_PAGES + 1):
        query = f"{PATTERN_SEARCH_TERMS[pattern_name]} pushed:{window_start.isoformat()}..{window_end.isoformat()}"
        url = f"https://api.github.com/search/code?q={query}&per_page={PER_PAGE}&page={page}"
        try:
            data = await fetch_github(url)
        except GitHubLimitExceeded as gle:
            duration = window_end - window_start
            if duration >= timedelta(minutes=MIN_WINDOW_MINUTES * 2):
                mid = window_start + duration / 2
                logger.info(f"Subdividing window for {pattern_name}: {window_start.isoformat()} to {window_end.isoformat()}")
                left = await scan_window(pattern_name, window_start, mid)
                right = await scan_window(pattern_name, mid, window_end)
                return left + right
            else:
                logger.warning(f"Window too small to subdivide for {pattern_name}: {window_start.isoformat()} to {window_end.isoformat()}")
                return all_matches
        items = data.get("items", [])
        if not items:
            break
        # Instead of processing and inserting here, we only extract matches.
        tasks = [find_matches(item) for item in items]
        page_matches_lists = await asyncio.gather(*tasks, return_exceptions=True)
        for m in page_matches_lists:
            if not isinstance(m, Exception):
                all_matches.extend(m)
    return all_matches

# Celery task for scanning a window returns a list of match dictionaries.
@celery.task(name="celery_scan_window", queue="github_scan")
def celery_scan_window(pattern_name, window_start_str, window_end_str):
    window_start = datetime.fromisoformat(window_start_str)
    window_end = datetime.fromisoformat(window_end_str)
    try:
        matches = worker_loop.run_until_complete(scan_window(pattern_name, window_start, window_end))
        return matches  # This is a list (possibly empty) of match dictionaries.
    except Exception as e:
        logger.error(f"celery_scan_window failed for {pattern_name} window {window_start_str} to {window_end_str}: {str(e)}")
        # On error, return an empty list so that no matches are lost.
        return []

# --- Worker Stage 2: Storing Matches into the Database ---
@celery.task(name="store_matches", queue="db_store")
def store_matches(matches):
    try:
        result = worker_loop.run_until_complete(store_matches_async(matches))
        return result
    except Exception as e:
        logger.error(f"store_matches failed: {str(e)}")
        return 0

async def store_matches_async(matches):
    inserted = 0
    async with global_pool.acquire() as conn:
        for match in matches:
            row = await conn.fetchrow(
                "SELECT id FROM leaked_keys WHERE repo_url=$1 AND file_path=$2 AND leaked_key=$3",
                match["repo_url"], match["file_path"], match["leaked_key"]
            )
            if row:
                logger.info(f"Match already exists: {match['repo_url']}/{match['file_path']}")
                continue
            row = await conn.fetchrow(
                "INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key) VALUES ($1, $2, $3, $4) RETURNING id",
                match["repo_url"], match["file_path"], match["key_type"], match["leaked_key"]
            )
            inserted += 1
            logger.info(f"Inserted match: {match['leaked_key'][:10]}... (ID: {row['id']})")
    return inserted

# --- Dispatching Tasks in Batches (Window Chain) ---
# Now each window chain becomes a pipeline: scan then store.
@celery.task(name="dispatch_window", queue="window_dispatch")
def dispatch_window(_, pattern_name, window_start_str, window_end_str, now_str):
    window_end = datetime.fromisoformat(window_end_str)
    now = datetime.fromisoformat(now_str)
    logger.info(f"Completed window for {pattern_name}: {window_start_str} to {window_end_str}")
    # Chain the scanning task with the storing task.
    chain_result = chain(
        celery_scan_window.s(pattern_name, window_start_str, window_end_str),
        store_matches.s()
    ).delay()
    # Schedule the next window if needed.
    if window_end < now:
        next_start = window_end
        next_end = min(next_start + timedelta(minutes=WINDOW_MINUTES), now)
        tasks = [chain(celery_scan_window.s(pattern_name, next_start.isoformat(), next_end.isoformat()) | store_matches.s())]
        chord(tasks)(dispatch_window.s(pattern_name, next_start.isoformat(), next_end.isoformat(), now_str))
    else:
        logger.info(f"All windows complete for pattern: {pattern_name}")

@celery.task(name="dispatch_all_scans", queue="dispatcher")
def dispatch_all_scans():
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()
    for pattern_name in PATTERN_SEARCH_TERMS.keys():
        start_time = now - timedelta(days=DEFAULT_DAYS)
        window_end = min(start_time + timedelta(minutes=WINDOW_MINUTES), now)
        # For each window, create a chain: scan then store.
        chain_result = chain(
            celery_scan_window.s(pattern_name, start_time.isoformat(), window_end.isoformat()),
            store_matches.s()
        ).delay()
        # Then schedule subsequent windows via dispatch_window.
        chord([chain(celery_scan_window.s(pattern_name, start_time.isoformat(), window_end.isoformat()) | store_matches.s())])(
            dispatch_window.s(pattern_name, start_time.isoformat(), window_end.isoformat(), now_str)
        )
# --- End Task Dispatching ---

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
