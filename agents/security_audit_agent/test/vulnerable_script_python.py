#!/usr/bin/env python3
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_user():
    username = request.args.get('username')
    
    # Vulnerability 1: String formatting with %
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    results = cursor.fetchall()
    
    # Vulnerability 2: String concatenation
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    user_data = cursor.fetchone()
    
    # Vulnerability 3: f-string interpolation
    email = request.args.get('email')
    cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
    email_results = cursor.fetchall()
    
    conn.close()
    return render_template('results.html', results=results, user_data=user_data, email_results=email_results)

@app.route('/admin', methods=['POST'])
def admin_login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Vulnerability 4: Dangerous direct input in executescript
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    admin_query = f"SELECT * FROM admins WHERE username = '{username}' AND password = '{password}'"
    cursor.executescript(admin_query)
    
    return "Login attempt processed"

if __name__ == '__main__':
    app.run(debug=True) 