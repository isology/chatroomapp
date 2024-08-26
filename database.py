import sqlite3

# Create a connection to the SQLite database
conn = sqlite3.connect('chat_users.db')
cursor = conn.cursor()

# Create a table to store user credentials
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
)
''')

# Insert some users (you can do this manually or through code)
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user1", "password1"))
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("user2", "password2"))

# Commit the changes and close the connection
conn.commit()
conn.close()
