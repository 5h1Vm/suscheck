import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Malicious: String interpolation makes it vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchall()
    return result

# Subprocess shell injection
import subprocess
def run_command(user_input):
    # Malicious: shell=True with user input
    subprocess.Popen("ls -la " + user_input, shell=True)
