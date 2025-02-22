from flask import Flask, Response
import requests
import re
import time
import os
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
import logging
from dotenv import load_dotenv
import sys
import queue
from threading import Thread, Lock
import concurrent.futures

# Load environment variables
load_dotenv()

# GitHub API Credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}

# Database Configuration
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT", "5432"),
}

# API Key Patterns (precompiled)
API_PATTERNS = {
    "OpenAI": r"OPEN_API_KEY=sk-[a-zA-Z0-9]{48}",
    "AWS": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
}
COMPILED_PATTERNS = {k: re.compile(v) for k, v in API_PATTERNS.items()}

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Create a queue to capture log messages for streaming
log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.queue = q

    def emit(self, record):
        log_entry = self.format(record)
        self.queue.put(log_entry)

queue_handler = QueueHandler(log_queue)
queue_handler.setLevel(logging.INFO)
queue_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.getLogger().addHandler(queue_handler)

app = Flask(__name__)

# Global lock for logging unique count (optional)
unique_lock = Lock()

def setup_db():
    # Use a temporary connection to set up the table
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
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
                conn.commit()
                logging.info("Database setup complete.")
    except Exception as e:
        logging.error(f"Error setting up database: {e}")

def maybe_sleep_for_rate_limit(response):
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset_time = response.headers.get("X-RateLimit-Reset")
    if remaining is not None:
        try:
            remaining = int(remaining)
            if remaining < 5:
                if reset_time:
                    reset_epoch = int(reset_time)
                    current_epoch = int(time.time())
                    sleep_seconds = min(reset_epoch - current_epoch, 120)
                    if sleep_seconds > 0:
                        logging.warning(f"Near rate limit! Sleeping for {sleep_seconds}s.")
                        time.sleep(sleep_seconds)
                else:
                    logging.warning("Near rate limit! Sleeping for 60s.")
                    time.sleep(60)
        except ValueError:
            pass

def search_github(per_page=100, max_pages=1000):
    search_terms = ["OPEN_API_KEY=sk-", "AKIA", "AIza", "sk_live_", "xoxb", "ghp_"]
    all_results = []
    for query in search_terms:
        page = 1
        while page <= max_pages:
            url = f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}"
            try:
                response = requests.get(url, headers=HEADERS)
                maybe_sleep_for_rate_limit(response)
                if response.status_code == 403:
                    time.sleep(60)
                    continue
                if response.status_code != 200:
                    break
                items = response.json().get("items", [])
                if not items:
                    break
                all_results.extend(items)
            except Exception as e:
                logging.error(f"GitHub API request failed: {e}")
                break
            page += 1
            time.sleep(2)
    return all_results

def extract_keys(content):
    found_keys = []
    for key_type, compiled in COMPILED_PATTERNS.items():
        matches = compiled.findall(content)
        for match in matches:
            found_keys.append((key_type, match))
    return found_keys

def fetch_raw_content(item):
    download_url = item.get("download_url")
    file_url = download_url if download_url else item.get("html_url")
    if not file_url:
        return None, None
    try:
        response = requests.get(file_url, headers=HEADERS)
        maybe_sleep_for_rate_limit(response)
        if response.status_code != 200:
            return file_url, None
        return file_url, response.text
    except Exception as e:
        logging.error(f"Error fetching file content from {file_url}: {e}")
        return file_url, None

def process_item(item, pool):
    """Process a single GitHub item: fetch content, extract keys, and insert unique keys into the DB.
       Returns the number of new unique keys inserted.
    """
    try:
        repo_url = item["repository"]["html_url"]
        file_path = item["path"]
        logging.info(f"Processing file: {repo_url}/{file_path}")
        actual_url, content = fetch_raw_content(item)
        if not content:
            logging.info(f"Failed to fetch content for {actual_url}")
            return 0

        leaked_keys = extract_keys(content)
        if not leaked_keys:
            logging.info(f"No keys found in {actual_url}")
            return 0

        unique_in_item = 0
        conn = pool.getconn()
        try:
            with conn.cursor() as cursor:
                for key_type, leaked_key in leaked_keys:
                    # Check for duplicate entry
                    cursor.execute("""
                        SELECT id FROM leaked_keys
                        WHERE repo_url = %s AND file_path = %s AND leaked_key = %s
                    """, (repo_url, file_path, leaked_key))
                    if cursor.fetchone():
                        logging.info(f"Key already exists for {repo_url}/{file_path}")
                        continue

                    cursor.execute("""
                        INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id;
                    """, (repo_url, file_path, key_type, leaked_key))
                    new_id = cursor.fetchone()[0]
                    conn.commit()
                    with unique_lock:
                        unique_in_item += 1
                    logging.info(f"Unique key: {leaked_key[:10]}... | Inserted ID: {new_id}")
            return unique_in_item
        except Exception as e:
            logging.error(f"Database error for {repo_url}/{file_path}: {e}")
            conn.rollback()
            return 0
        finally:
            pool.putconn(conn)
    except Exception as e:
        logging.error(f"Error processing item: {e}")
        return 0

def run_scan():
    logging.info("Starting scan...")
    setup_db()
    results = search_github()
    logging.info(f"Fetched {len(results)} GitHub results.")
    if not results:
        logging.info("No results returned from GitHub API.")
        logging.info("Scan complete.")
        return

    # Create a threaded connection pool
    pool = ThreadedConnectionPool(1, 10, **DB_CONFIG)
    total_unique = 0

    # Process GitHub items concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_item, item, pool) for item in results]
        for future in concurrent.futures.as_completed(futures):
            try:
                count = future.result()
                total_unique += count
            except Exception as e:
                logging.error(f"Error in worker thread: {e}")

    pool.closeall()
    logging.info(f"Scan complete. Total unique keys saved: {total_unique}")

# The /scan endpoint now starts the scan in a background thread and streams log messages.
@app.route('/scan', methods=['GET'])
def scan():
    scan_thread = Thread(target=run_scan)
    scan_thread.start()

    # Generator to stream log messages from the queue
    def generate():
        while scan_thread.is_alive() or not log_queue.empty():
            try:
                msg = log_queue.get(timeout=1)
                yield msg + "\n"
            except queue.Empty:
                continue

    headers = {
        "Content-Type": "text/plain",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    }
    return Response(generate(), headers=headers)

if __name__ == '__main__':
    # Bind to the appropriate port for Render or default to 5000
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
