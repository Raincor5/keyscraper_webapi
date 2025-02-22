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

# Set up logging to print to stdout for Render compatibility
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
    """Sets up the leaked_keys table with a UNIQUE constraint on leaked_key."""
    conn = connect_db()
    if not conn:
        return

    cursor = conn.cursor()
    try:
        logging.info("⚙️ Setting up database...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS leaked_keys (
                id SERIAL PRIMARY KEY,
                repo_url TEXT NOT NULL,
                file_path TEXT NOT NULL,
                key_type TEXT NOT NULL,
                leaked_key TEXT NOT NULL UNIQUE,
                detected_at TIMESTAMP DEFAULT NOW(),
                notified BOOLEAN DEFAULT FALSE
            );
        """)
        conn.commit()
        logging.info("✅ Database setup complete.")
    except Exception as e:
        logging.error(f"❌ Error setting up database: {e}")
        conn.rollback()
    finally:
        conn.close()

def search_github(per_page=100, max_pages=1000):
    """
    Fetch all pages of results for leaked API keys from GitHub.
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

                if response.status_code == 403:
                    logging.warning("⏳ Rate limit hit! Sleeping for 60 seconds...")
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
            time.sleep(2)

    logging.info(f"📊 Total results fetched: {len(all_results)}")
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
    logging.info(f"📌 Extracted {len(found_keys)} API keys from this file's content.")
    return found_keys

def process_results(results):
    """
    Takes the items from GitHub search, fetches file content,
    extracts keys, and inserts them into the leaked_keys table.
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
        file_url = item["html_url"]  # GitHub "html_url" often gives the webpage, not raw content.
                                     # If you need raw content, use "download_url" from another API response.

        logging.info(f"📄 Processing file: {file_url}")

        # Fetch file content
        try:
            file_response = requests.get(file_url, headers=HEADERS)
            if file_response.status_code != 200:
                logging.warning(f"⚠️ Failed to fetch file content: {file_url} (status: {file_response.status_code})")
                continue

            content = file_response.text
        except Exception as e:
            logging.error(f"❌ Error fetching file content from {file_url}: {e}")
            continue

        leaked_keys = extract_keys(content)
        if not leaked_keys:
            logging.debug(f"ℹ️ No keys found in {file_url}. Moving on.")
            continue

        for key_type, leaked_key in leaked_keys:
            try:
                cursor.execute(
                    """
                    INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (leaked_key) DO NOTHING
                    RETURNING id;
                    """,
                    (repo_url, file_path, key_type, leaked_key)
                )

                # If RETURNING id returns a row, it means a new record was inserted
                inserted_id = cursor.fetchone()
                if inserted_id:
                    total_inserted += 1
                    logging.info(f"✅ Inserted {key_type} key from {file_path} (ID: {inserted_id[0]})")
                else:
                    logging.info(f"🤔 Key {leaked_key[:10]}... already exists; skipped insertion.")

            except psycopg2.Error as e:
                logging.error(f"❌ Database insertion error: {e}")
                conn.rollback()  # rollback this transaction
            # else we keep going within this file

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
