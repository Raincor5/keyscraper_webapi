import requests
import re
import time
import os
import psycopg2
import logging
from dotenv import load_dotenv
import sys

# Load Environment Variables
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

# API Key Patterns
API_PATTERNS = {
    "OpenAI": r"OPEN_API_KEY=sk-[a-zA-Z0-9]{48}",
    "AWS": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
}

# Configure logging to stdout for Render or other platforms
logging.basicConfig(
    level=logging.DEBUG,  # More verbose logging
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logging.info("🔍 Script started: Searching for leaked API keys.")

def connect_db():
    """Connects to PostgreSQL and returns the connection."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        logging.info("✅ Connected to the database successfully.")
        return conn
    except Exception as e:
        logging.error(f"❌ Database connection error: {e}")
        return None

def setup_db():
    """
    Sets up the leaked_keys table without a UNIQUE constraint
    (we'll handle duplicates manually).
    """
    conn = connect_db()
    if not conn:
        return

    cursor = conn.cursor()
    try:
        logging.info("⚙️ Setting up database (removing UNIQUE constraint)...")
        # Drop table if you want a fresh start each time (optional):
        # cursor.execute("DROP TABLE IF EXISTS leaked_keys;")

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
        logging.info("✅ Database setup complete (no unique constraint).")
    except Exception as e:
        logging.error(f"❌ Error setting up database: {e}")
        conn.rollback()
    finally:
        conn.close()

def maybe_sleep_for_rate_limit(response):
    """
    Parses GitHub rate-limit headers and sleeps if we are dangerously close to the limit.
    """
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset_time = response.headers.get("X-RateLimit-Reset")

    if remaining is not None:
        try:
            remaining = int(remaining)
            if remaining < 5:  # If we have fewer than 5 requests left
                # Sleep until reset if possible
                if reset_time:
                    # Convert reset_time to int, then to seconds from epoch
                    reset_epoch = int(reset_time)
                    current_epoch = int(time.time())
                    sleep_seconds = reset_epoch - current_epoch
                    # Sleep for at most 2 minutes, or the difference
                    sleep_seconds = min(sleep_seconds, 120)
                    if sleep_seconds > 0:
                        logging.warning(f"⏳ Near rate limit! Sleeping for {sleep_seconds}s until reset.")
                        time.sleep(sleep_seconds)
                else:
                    # fallback: just sleep 60 seconds
                    logging.warning("⏳ Near rate limit! No reset header. Sleeping 60s.")
                    time.sleep(60)
        except ValueError:
            pass

def search_github(per_page=100, max_pages=100):
    """
    Fetch all pages of results for leaked API keys from GitHub.
    Uses 'download_url' if available for raw content.
    Adjust 'search_terms' or 'max_pages' for deeper scans.
    """
    search_terms = ["OPEN_API_KEY=sk-", "AKIA", "AIza", "sk_live_", "xoxb", "ghp_"]
    all_results = []

    for query in search_terms:
        page = 1
        while page <= max_pages:
            url = f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}"
            logging.info(f"🔍 Searching GitHub: '{query}' (Page {page})")

            try:
                response = requests.get(url, headers=HEADERS)
                logging.info(f"🔄 GitHub API Response: {response.status_code}")

                # Check rate limit
                maybe_sleep_for_rate_limit(response)

                if response.status_code == 403:
                    logging.warning("⏳ Rate limit hit! Sleeping 60 seconds...")
                    time.sleep(60)
                    continue

                if response.status_code != 200:
                    logging.error(f"❌ GitHub API Error: {response.status_code} - {response.text}")
                    break

                items = response.json().get("items", [])
                if not items:
                    logging.info(f"✅ No more results for '{query}' on Page {page}. Stopping.")
                    break

                all_results.extend(items)
                logging.info(f"✅ Fetched {len(items)} results from '{query}' on Page {page}.")

            except Exception as e:
                logging.error(f"❌ GitHub API request failed: {e}")
                break

            page += 1
            # Sleep 2 seconds to avoid spamming the server
            time.sleep(2)

    logging.info(f"📊 Total GitHub search results fetched: {len(all_results)}")
    return all_results

def extract_keys(content):
    """
    Applies each regex in API_PATTERNS to the file content
    and returns a list of (key_type, key_value) for all matches.
    """
    found_keys = []
    for key_type, pattern in API_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            found_keys.append((key_type, match))
            logging.debug(f"🔑 Found {key_type} key: {match[:10]}... (truncated)")
    logging.info(f"📌 Extracted {len(found_keys)} total API keys from this file's content.")
    return found_keys

def fetch_raw_content(item):
    """
    Tries to retrieve the raw file content using 'download_url'.
    If not available, uses 'html_url' as a fallback (though HTML may be less reliable).
    """
    download_url = item.get("download_url")
    file_url = download_url if download_url else item.get("html_url")

    if not file_url:
        logging.warning("⚠️ No valid URL found for raw content.")
        return None, None

    # Return both the actual URL used and the content
    try:
        response = requests.get(file_url, headers=HEADERS)
        maybe_sleep_for_rate_limit(response)
        if response.status_code != 200:
            logging.warning(f"⚠️ Failed to fetch raw content: {file_url} (status {response.status_code})")
            return file_url, None
        return file_url, response.text
    except Exception as e:
        logging.error(f"❌ Error fetching file content from {file_url}: {e}")
        return file_url, None

def process_results(results):
    """
    Takes the items from GitHub search, fetches file content (raw if possible),
    extracts keys, and inserts them into the leaked_keys table
    AFTER checking for duplicates manually.
    """
    conn = connect_db()
    if not conn:
        logging.error("❌ Database connection failed. Cannot process results.")
        return

    cursor = conn.cursor()

    total_inserted = 0  # Track how many new records we insert

    for item in results:
        repo_url = item["repository"]["html_url"]
        file_path = item["path"]

        # Attempt to fetch raw content
        actual_url, content = fetch_raw_content(item)
        if not content:
            logging.debug(f"ℹ️ No content returned for {actual_url}. Skipping.")
            continue

        logging.info(f"📄 Processing file: {actual_url}")

        leaked_keys = extract_keys(content)
        if not leaked_keys:
            logging.debug(f"ℹ️ No keys found in {actual_url}. Moving on.")
            continue

        for key_type, leaked_key in leaked_keys:
            try:
                # Manual duplicate check: 
                # We'll treat duplicates as same repo_url + file_path + leaked_key
                cursor.execute("""
                    SELECT id
                    FROM leaked_keys
                    WHERE repo_url = %s
                      AND file_path = %s
                      AND leaked_key = %s
                """, (repo_url, file_path, leaked_key))
                existing = cursor.fetchone()

                if existing:
                    logging.info(f"🤔 Key already in DB for {repo_url}, {file_path}. Skipping.")
                else:
                    cursor.execute(
                        """
                        INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id;
                        """,
                        (repo_url, file_path, key_type, leaked_key)
                    )
                    new_id = cursor.fetchone()[0]
                    total_inserted += 1
                    logging.info(f"✅ Inserted new {key_type} key (ID: {new_id}) from {file_path}.")

            except psycopg2.Error as e:
                logging.error(f"❌ Database insertion error: {e}")
                conn.rollback()
                continue

    # Attempt to commit the entire batch
    try:
        conn.commit()
        logging.info(f"✅ Database transaction committed. {total_inserted} new records inserted in total.")
    except Exception as e:
        logging.error(f"❌ Error committing transaction: {e}")
        conn.rollback()
    finally:
        conn.close()

def main():
    logging.info("🚀 Starting API key scanning process...")
    setup_db()

    results = search_github()
    if results:
        process_results(results)
    else:
        logging.info("ℹ️ No items returned from the GitHub API search.")

    logging.info("🏁 Execution complete.")

if __name__ == "__main__":
    main()
