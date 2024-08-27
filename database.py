import sqlite3

def create_users_table():
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    
    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("ismail", "ismail"))
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("ali", "ali"))

    
    conn.commit()
    conn.close()
    print("Users table created successfully.")

if __name__ == "__main__":
    create_users_table()
