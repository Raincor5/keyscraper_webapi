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

# Regex Patterns for API Keys
API_PATTERNS = {
    "AWS": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack": r"xox[baprs]-[0-9A-Za-z]{10,48}",
}

# Connect to Database
def connect_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)  # Switch to pymysql.connect for MySQL
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# Create Table if Not Exists
def setup_db():
    conn = connect_db()
    if not conn:
        return

    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS leaked_keys (
            id SERIAL PRIMARY KEY,
            repo_url TEXT,
            file_path TEXT,
            key_type TEXT,
            leaked_key TEXT,
            detected_at TIMESTAMP DEFAULT NOW(),
            notified BOOLEAN DEFAULT FALSE
        );
    """)
    conn.commit()
    conn.close()

# GitHub API Search
def search_github(query, per_page=10):
    url = f"https://api.github.com/search/code?q={query}&per_page={per_page}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 403:  # Rate limit handling
        print("Rate limited! Sleeping for 60 seconds...")
        time.sleep(60)
        return search_github(query, per_page)

    return response.json().get("items", [])

# Extract API Keys from Code
def extract_keys(content):
    found_keys = []
    for key_type, pattern in API_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            found_keys.append((key_type, match))
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

        # Get file content
        file_response = requests.get(file_url, headers=HEADERS)
        if file_response.status_code != 200:
            continue

        content = file_response.text
        leaked_keys = extract_keys(content)

        for key_type, leaked_key in leaked_keys:
            cursor.execute("""
                INSERT INTO leaked_keys (repo_url, file_path, key_type, leaked_key)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (leaked_key) DO NOTHING;
            """, (repo_url, file_path, key_type, leaked_key))

    conn.commit()
    conn.close()

# Main Execution
def main():
    setup_db()
    search_terms = ["API_KEY", "SECRET_KEY", "access_token", "AWS_SECRET", "GOOGLE_API_KEY"]
    
    for term in search_terms:
        print(f"Searching for: {term}")
        results = search_github(term)
        process_results(results)
        time.sleep(5)  # Prevent hitting rate limits

if __name__ == "__main__":
    main()
