import anthropic
import sqlite3
import csv
from typing import Literal, Optional

from pydantic import BaseModel, Field
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

client = anthropic.Anthropic()


class LogFields(BaseModel):
    """Schema Claude must fill in for a single SSH log entry."""
    ip_address: Optional[str] = Field(description="The IP address involved, null if absent")
    username: Optional[str] = Field(description="The username attempted, null if absent")
    failure_reason: Optional[str] = Field(
        description='Reason for failure, e.g. "Invalid user", "Failed password"'
    )
    event_type: Literal["failed_login", "invalid_user", "accepted", "disconnected", "other"] = Field(
        description="The kind of event this entry records"
    )
    port: Optional[int] = Field(description="Port number if present, null if absent")


def extract_log_fields(content: str) -> LogFields:
    """Send one log content string to claude, get structured fields back.

    output_format constrains the response to the LogFields schema, so the
    result is always valid and already typed - no JSON parsing needed.
    """
    response = client.messages.parse(
        model="claude-haiku-4-5",
        max_tokens=200,
        messages=[
            {"role": "user", "content": f"Extract structured information from this SSH log entry: {content}"}
        ],
        output_format=LogFields,
    )
    return response.parsed_output


def setup_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ssh_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            pid TEXT,
            raw_content TEXT,
            ip_address TEXT,
            username TEXT,
            failure_reason TEXT,
            event_type TEXT,
            port TEXT
        )
    """)
    conn.commit()

def process_logs(csv_path: str, db_path: str, limit: int = 50):
    """Read CSV, extract fields via LLM, store in SQLite."""
    conn = sqlite3.connect(db_path)
    setup_db(conn)

    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)

        for i, row in enumerate(reader):
            if i >= limit:
                break

            content = row.get("Content", "")
            if not content:
                continue

            print(f"[{i+1}] Processing: {content[:60]}...")
            extracted = extract_log_fields(content)

            conn.execute("""
                INSERT INTO ssh_logs
                (timestamp, pid, raw_content, ip_address, username, failure_reason, event_type, port)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row.get("Time"),
                row.get("Pid"),
                content,
                extracted.ip_address,
                extracted.username,
                extracted.failure_reason,
                extracted.event_type,
                extracted.port
            ))
            conn.commit()

    conn.close()
    print("Done.")

def find_brute_force(db_path: str, threshold: int = 5):
    conn = sqlite3.connect(db_path)
    results = conn.execute("""
        SELECT ip_address, COUNT(*) as attempts
        from ssh_logs
        WHERE event_type IN ('failed_login', 'invalid_user')
        AND ip_address IS NOT NULL
        GROUP BY ip_address
        HAVING attempts >= ?
        ORDER BY attempts DESC
    """, (threshold,)).fetchall()
    conn.close()
    return results

if __name__ == "__main__":
    process_logs("data/OpenSSH_2k.log_structured.csv", "ssh_logs.db", limit=50)
    suspects = find_brute_force("ssh_logs.db", threshold=5)
    print(f"\nBrute force suspects: {len(suspects)}")
    for ip, count in suspects:
        print(f"{ip}: {count} attempts")
