from flask import Flask,request,render_template,jsonify,session,redirect,url_for
import mysql.connector
from datetime import datetime, time, timedelta

import json
import bcrypt
import os
import re
from flask import Flask
# app=Flask(__name__)
app = Flask(__name__, static_url_path='/static')

app.secret_key = os.urandom(24)  # Generates a random key each time the server restarts

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'voter_interface'

def create_connection():
    print("calling this connection")
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )

@app.route('/create_table')
def create_table():
    print("calling this function")
    connection = create_connection()
    print("this is connection",connection)
    cursor = connection.cursor()
    create_user_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            aadhar_number VARCHAR(12) UNIQUE NOT NULL,
            password VARCHAR(64) NOT NULL
        );"""
    cursor.execute(create_user_table_query)

    # Create Candidates Table
    create_candidates_table_query="""
        CREATE TABLE IF NOT EXISTS candidates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL,
            party VARCHAR(100) NOT NULL,
            votes INT DEFAULT 0
        );"""
    cursor.execute(create_candidates_table_query)
    # Create Votes Table (To prevent multiple votes)
    create_votes_table_query = """
    CREATE TABLE IF NOT EXISTS votes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        voter_id INT UNIQUE NOT NULL,
        candidate_id INT NOT NULL,
        encrypted_vote TEXT,
        FOREIGN KEY (voter_id) REFERENCES users(id),
        FOREIGN KEY (candidate_id) REFERENCES candidates(id)
    );
"""
    cursor.execute(create_votes_table_query)
    create_admin_table_query = """
        CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(64) NOT NULL
        );
    """
    cursor.execute(create_admin_table_query)
    connection.commit()
    cursor.close()
    connection.close()
    return "Table 'users' created successfully!"

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'GET':
            return render_template('register.html', message=None)

        data = request.form

        username = data.get('username')
        aadhar_number = data.get('aadhar_number')
        password = data.get('password')

        # Basic validation
        if not username or not aadhar_number or not password:
            return render_template('register.html', message="All fields are required!")

        # Aadhar number must be exactly 12 digits
        if not re.fullmatch(r'\d{12}', aadhar_number):
            return render_template('register.html', message="Aadhar number must be 12 digits!")

        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR aadhar_number = %s", (username, aadhar_number))
        existing_user = cursor.fetchone()
        if existing_user:
            return render_template('register.html', message="Username or Aadhar already exists!")

        # Hash and insert
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, aadhar_number, password) VALUES (%s, %s, %s)",
            (username, aadhar_number, hashed_password.decode('utf-8'))
        )
        connection.commit()
        cursor.close()
        connection.close()

        return render_template('register.html', message="Voter registered successfully!")

    except Exception as e:
        return render_template('register.html', message=f"Error: {str(e)}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.content_type == 'application/json':
            data = request.get_json()
        else:
            data = request.form

        aadhar_number = data.get('aadhar_number')
        password = data.get('password')

        if not aadhar_number or not password:
            return jsonify({"error": "Aadhar number and password are required!"}), 400

        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Fetch user by Aadhar number
        cursor.execute("SELECT * FROM users WHERE aadhar_number = %s", (aadhar_number,))
        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['username'] = user['username']  # Store in session
            return jsonify({"message": "Login successful!"})
        else:
            return jsonify({"error": "Invalid Aadhar number or password!"}), 401

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove user from session
    return redirect(url_for('home'))  # Redirect to login page

@app.route('/candidates', methods=['GET'])
def get_candidates():
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM candidates")
        candidates = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify(candidates)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
from aes_utils import encrypt_vote  # Make sure this file is created and imported

@app.route('/vote', methods=['POST'])
def cast_vote():
    try:
        if 'username' not in session:
            return jsonify({"error": "User not logged in!"}), 401
        
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "Invalid user!"}), 400

        voter_id = user['id']
        data = request.json
        candidate_id = str(data['candidate_id'])  # Convert to string for encryption

        # Check if voter already voted
        cursor.execute("SELECT * FROM votes WHERE voter_id = %s", (voter_id,))
        existing_vote = cursor.fetchone()

        if existing_vote:
            return jsonify({"error": "You have already voted!"}), 403

        # Encrypt the vote
        secret_key = "YourSecretKey123"  #  Use a consistent & secure key
        encrypted_vote = encrypt_vote(candidate_id, secret_key)

        # Insert encrypted vote into the votes table
        cursor.execute("INSERT INTO votes (voter_id, candidate_id, encrypted_vote) VALUES (%s, %s, %s)",
                       (voter_id, candidate_id, encrypted_vote))

        # Increment the vote count for the candidate
        cursor.execute("UPDATE candidates SET votes = votes + 1 WHERE id = %s", (candidate_id,))

        # Commit changes to the database
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({"message": "Vote cast successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_results', methods=['GET'])
def get_results():
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM candidates")  # Get the candidates and their details
        candidates = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify(candidates)  # Return the results as JSON

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def home():
    return render_template("index.html")
@app.route('/login_page')
def login_page():
    return render_template('login.html')
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']
        
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM admins WHERE username = %s", (username,))
        existing_admin = cursor.fetchone()
        
        if existing_admin:
            return jsonify({"error": "Admin username already exists!"}), 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        insert_query = "INSERT INTO admins (username, password) VALUES (%s, %s)"
        cursor.execute(insert_query, (username, hashed_password.decode('utf-8')))
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return redirect(url_for('admin_login'))
    
    return render_template('admin_register.html')
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')

        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM admins WHERE username = %s", (username,))
        admin = cursor.fetchone()

        cursor.close()
        connection.close()

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
            session['admin_username'] = admin['username']
            print("Admin Logged In Successfully! Session Set:", session)  # Debug
            return redirect(url_for('admin_dashboard'))
        else:
            return jsonify({"error": "Invalid credentials"}), 401  

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)

    # Fetch election results (candidate details and votes)
    cursor.execute("SELECT id, name, party, votes FROM candidates")
    results = cursor.fetchall()

    # Extract data for Chart.js
    candidate_names = [row['name'] for row in results]
    vote_counts = [row['votes'] for row in results]
    candidate_parties = [row['party'] for row in results]

    cursor.close()
    connection.close()

    return render_template('admin_dashboard.html', 
                           results=results, 
                           candidate_names=candidate_names, 
                           vote_counts=vote_counts, 
                           candidate_parties=candidate_parties)


@app.route('/add_candidates', methods=['POST', 'GET'])
def add_candidates():
    if 'admin_username' not in session:  # Check if admin is logged in
        return redirect(url_for('admin_login'))  # Redirect if not logged in

    if request.method == 'POST':
        try:
            data = request.form
            name = data.get('name')
            party = data.get('party')

            # Ensure all fields are provided
            if not name or not party:
                return jsonify({"error": "All fields are required!"}), 400

            connection = create_connection()
            cursor = connection.cursor()

            # Insert candidate into the database
            insert_query = "INSERT INTO candidates (name, party) VALUES (%s, %s)"
            cursor.execute(insert_query, (name, party))

            connection.commit()
            cursor.close()
            connection.close()

            return redirect(url_for('admin_dashboard'))  # Redirect after adding

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template('add_candidates.html')  # Render candidate addition form


@app.route('/admin/candidates', methods=['GET'])
def view_candidates():
    if 'admin_username' not in session:
        return jsonify({"error": "Unauthorized access!"}), 403
    
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM candidates")
        candidates = cursor.fetchall()
        
        cursor.close()
        connection.close()

        return jsonify(candidates)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/edit_candidate/<int:candidate_id>', methods=['GET', 'POST'])
def edit_candidate(candidate_id):
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM candidates WHERE id = %s", (candidate_id,))
    candidate = cursor.fetchone()

    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        
        cursor.execute("UPDATE candidates SET name = %s, party = %s WHERE id = %s", (name, party, candidate_id))
        connection.commit()
        cursor.close()
        connection.close()

        return redirect(url_for('admin_dashboard'))

    cursor.close()
    connection.close()
    return render_template('edit_candidate.html', candidate=candidate)


@app.route('/delete_candidate/<int:candidate_id>', methods=['GET'])
def delete_candidate(candidate_id):
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM candidates WHERE id = %s", (candidate_id,))
    connection.commit()
    
    cursor.close()
    connection.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/results', methods=['GET'])
def admin_results():
    if 'admin_username' not in session:
        return jsonify({"error": "Unauthorized access!"}), 403
    
    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT name, party, votes FROM candidates ORDER BY votes DESC")
        results = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_username', None)  # Remove admin from session
    return redirect(url_for('admin_login'))  # Redirect to admin login


if "__main__"==__name__:
    app.run(debug=True,host='0.0.0.0')
