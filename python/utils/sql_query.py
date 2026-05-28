import sqlite3

# A03:Injection — SQL Injection
# User-controlled input concatenated directly into a SQL query string.
# An attacker can supply: ' OR '1'='1 to dump all rows, or use UNION-based exfiltration.

def get_user_by_username(username: str) -> dict:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row

def search_products(keyword: str) -> list:
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + keyword + "%'")
    results = cursor.fetchall()
    conn.close()
    return results
