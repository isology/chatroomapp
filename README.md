This is a Chatroom app coded in Python.

Firstly open your vs code and open this project's folder, then run the server by running following code via terminal:
python server.py 127.0.0.1 -p 1060

Then open a cmd then navigate to path where your client.py located, then run this code via cd:
client.py 127.0.0.1

To check the database run this codes via terminal:
1) sqlite3 users.db
2) .tables
3) SELECT * FROM users;
(Valid output should be like this:
user|password
admin|adminpassword
)
