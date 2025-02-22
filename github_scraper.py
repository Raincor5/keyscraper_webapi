import requests
import re
import time
import os
import psycopg2  # PostgreSQL
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

# Regex Pattern for OpenAI API Keys
OPENAI_API_PATTERN = r"OPENAI_API_KEY=sk-[a-zA-Z0-9]{48}"

# Connect to Database
def connect_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)  # Switch to pymysql.connect for MySQL if needed
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def setup_db():
    conn = connect_db()
    if not conn:
        return

    cursor = conn.cursor()
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
    conn.close()

# GitHub API Search for OpenAI Keys
def search_github(per_page=10):
    query = "sk-"
    url = f"https://api.github.com/search/code?q={query}&per_page={per_page}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 403:  # Rate limit handling
        print("Rate limited! Sleeping for 60 seconds...")
        time.sleep(60)
        return search_github(per_page)

    return response.json().get("items", [])

# Extract OpenAI API Keys from Code
def extract_keys(content):
    return re.findall(OPENAI_API_PATTERN, content)

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

        # Get file content
        file_response = requests.get(file_url, headers=HEADERS)
        if file_response.status_code != 200:
            continue

        content = file_response.text
        leaked_keys = extract_keys(content)

        for leaked_key in leaked_keys:
            try:
                cursor.execute("""
                    INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (leaked_key) DO NOTHING;
                """, (repo_url, file_path, "OpenAI", leaked_key))
            except psycopg2.Error as e:
                print(f"Database insertion error: {e}")

    conn.commit()
    conn.close()

# Main Execution
def main():
    setup_db()
    print("Searching for OpenAI API keys...")
    results = search_github()
    process_results(results)
    time.sleep(5)  # Prevent hitting rate limits

if __name__ == "__main__":
    main()
