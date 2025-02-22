import requests
import re
import time
import os
import psycopg2
import logging
from dotenv import load_dotenv

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
    "port": os.getenv("DB_PORT", "5432"),  # Default to PostgreSQL port
}

# Regex Pattern for OpenAI API Keys (with "OPEN_API_KEY=" prefix)
OPENAI_API_PATTERN = r"OPEN_API_KEY=sk-[a-zA-Z0-9]{48}"

# Set up logging
logging.basicConfig(
    filename="leaked_keys.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Connect to Database
def connect_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)  # Switch to pymysql.connect for MySQL if needed
        logging.info("Connected to the database successfully.")
        return conn
    except Exception as e:
        logging.error(f"Database connection error: {e}")
        return None

def setup_db():
    conn = connect_db()
    if not conn:
        return

    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS leaked_keys (
                id SERIAL PRIMARY KEY,
                repo_url TEXT NOT NULL,
                file_path TEXT NOT NULL,
                key_type TEXT NOT NULL,
                leaked_key TEXT NOT NULL UNIQUE,  -- Ensure uniqueness
                detected_at TIMESTAMP DEFAULT NOW(),
                notified BOOLEAN DEFAULT FALSE
            );
        """)
        conn.commit()
        logging.info("Database setup completed with UNIQUE constraint on leaked_key.")
    except Exception as e:
        logging.error(f"Error setting up database: {e}")
        conn.rollback()
    finally:
        conn.close()


# GitHub API Search for OpenAI Keys
def search_github(per_page=1000, max_pages=100):
    """Fetch all pages of results for OpenAI API key leaks from GitHub."""
    query = "OPEN_API_KEY=sk-"
    page = 1
    all_results = []

    while page <= max_pages:
        url = f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}"
        logging.info(f"Fetching page {page}...")

        try:
            response = requests.get(url, headers=HEADERS)
            
            if response.status_code == 403:  # Rate limit handling
                logging.warning("Rate limited! Sleeping for 60 seconds...")
                time.sleep(60)
                continue  # Retry the same page after sleeping

            if response.status_code != 200:
                logging.error(f"GitHub API Error: {response.status_code} - {response.text}")
                break  # Stop fetching if there's an error

            items = response.json().get("items", [])
            if not items:
                logging.info(f"No more results found on page {page}. Stopping.")
                break  # Stop if GitHub returns no more results

            all_results.extend(items)
            logging.info(f"Fetched {len(items)} results from page {page}.")

        except Exception as e:
            logging.error(f"GitHub API request failed: {e}")
            break  # Stop on critical failure

        page += 1
        time.sleep(2)  # Delay to avoid hitting rate limits

    logging.info(f"Total results fetched: {len(all_results)}")
    return all_results


# Extract OpenAI API Keys from Code
def extract_keys(content):
    found_keys = re.findall(OPENAI_API_PATTERN, content)
    logging.info(f"Extracted {len(found_keys)} OpenAI API keys from content.")
    return found_keys

# Process Results & Store in DB
def process_results(results):
    conn = connect_db()
    if not conn:
        return

    cursor = conn.cursor()

    for item in results:
        repo_url = item["repository"]["html_url"]
        file_path = item["path"]
        file_url = item["html_url"]

        logging.info(f"Processing file: {file_url}")

        # Get file content
        try:
            file_response = requests.get(file_url, headers=HEADERS)
            if file_response.status_code != 200:
                logging.warning(f"Failed to fetch file content: {file_url}")
                continue

            content = file_response.text
        except Exception as e:
            logging.error(f"Error fetching file content: {e}")
            continue

        leaked_keys = extract_keys(content)

        for leaked_key in leaked_keys:
            try:
                cursor.execute("""
                    INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (leaked_key) DO NOTHING;
                """, (repo_url, file_path, "OpenAI", leaked_key))

                logging.info(f"Inserted key {leaked_key} from {file_path} into database.")

            except psycopg2.Error as e:
                logging.error(f"Database insertion error: {e}")
                conn.rollback()  # Rollback transaction if an error occurs

    try:
        conn.commit()
        logging.info("Database transaction committed successfully.")
    except Exception as e:
        logging.error(f"Error committing transaction: {e}")
        conn.rollback()
    finally:
        conn.close()

# Main Execution
def main():
    setup_db()
    logging.info("Starting search for OpenAI API keys...")

    results = search_github()
    if results:
        process_results(results)
    else:
        logging.info("No results found.")

    logging.info("Execution complete.")

if __name__ == "__main__":
    main()
