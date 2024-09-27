import os
from flask import Flask, request, jsonify, make_response, url_for
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import uuid
import redis
import mysql.connector
from mysql.connector import pooling
from flask import Flask
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from flask_cors import CORS



load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)
bcrypt = Bcrypt(app)
limiter = Limiter(app, key_func=get_remote_address)

# Environment variables
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
MYSQL_HOST = os.getenv('MYSQL_HOST')
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
MYSQL_DB = os.getenv('MYSQL_DATABASE')

# Redis connection
r = redis.StrictRedis(host='redis', port=6379, db=0)

# MySQL connection pool
db_config = {
    "host": MYSQL_HOST,
    "user": MYSQL_USER,
    "password": MYSQL_PASSWORD,
    "database": MYSQL_DB
}
connection_pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, **db_config)

def get_db_connection():
    return connection_pool.get_connection()

@app.route('/test-db')
def test_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return jsonify({"message": "Database connection successful", "result": result}), 200
    except Exception as e:
        return jsonify({"message": "Database connection failed", "error": str(e)}), 500

def generate_verification_token():
    return str(uuid.uuid4())

def send_verification_email(to_email, verification_link):
    subject = "Verify your account"
    message = f"Click the following link to verify your account: {verification_link}"
    
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def create_session(user_id):
    session_token = str(uuid.uuid4())
    expires_at = datetime.now() + timedelta(days=7)

    try:
        # Store session in Redis
        r.setex(session_token, timedelta(days=7), str(user_id))

        # Insert session into the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO sessions (session_token, user_id, expires_at) VALUES (%s, %s, %s)',
                       (session_token, user_id, expires_at))
        conn.commit()

    except mysql.connector.Error as err:
        # Log MySQL errors
        print(f"MySQL Error during session creation: {err}")
        conn.rollback()

    except Exception as e:
        # Log any general exceptions
        print(f"Error during session creation: {e}")

    finally:
        cursor.close()
        conn.close()

    return session_token

def check_session():
    session_token = request.cookies.get('session_token')
    
    if session_token:
        user_id = r.get(session_token)
        
        if user_id:
            # No need to cast user_id to int, as it is a UUID (string)
            return user_id.decode('utf-8')  # Decode it since it's in bytes
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute('SELECT user_id FROM sessions WHERE session_token = %s AND expires_at > NOW()', (session_token,))
            session = cursor.fetchone()
            
            if session:
                r.setex(session_token, timedelta(days=7), str(session['user_id']))
                return session['user_id']
        
        finally:
            cursor.close()
            conn.close()
    
    return None


@app.route('/')
def index():
    return jsonify({"message": "Hello, world!"})

@app.route('/get-session', methods=['POST'])
def get_session():
    user_id = check_session()
    
    if user_id:
        # If session exists, get user info from the database
        conn = get_db_connection()
        cursor = None
        
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()

            if user:
                return jsonify(user), 200
            else:
                return jsonify({"message": "User not found"}), 404
        
        except mysql.connector.Error as err:
            # Log the error and send a failure response
            print(f"MySQL Error: {err}")
            return jsonify({"message": "Database query error"}), 500
        
        finally:
            if cursor:  # Only close cursor if it was successfully created
                cursor.close()
            conn.close()
    
    else:
        # Session check failed
        return jsonify({"message": "User not authenticated"}), 403


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    verification_token = generate_verification_token()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert the user into the users table
        cursor.execute(
            'INSERT INTO users (name, email, password, phone_number, city, country, is_verified, verification_token) '
            'VALUES (%s, %s, %s, %s, %s, %s, 0, %s)',
            (data['name'], data['email'], hashed_password, data['phone_number'], data['city'], data['country'], verification_token)
        )

        # Fetch the newly inserted user's UUID
        cursor.execute('SELECT id FROM users WHERE email = %s', (data['email'],))
        user_id = cursor.fetchone()[0]
        print("Fetched user_id:", user_id)  # Debugging statement

        # Insert into global_contacts table
        cursor.execute(
            'INSERT INTO global_contacts (phone_number, name, registered_user_id) VALUES (%s, %s, %s)',
            (data['phone_number'], data['name'], user_id)
        )

        conn.commit()

        # Send verification email
        verification_link = url_for('verify_email', token=verification_token, _external=True)
        if send_verification_email(data['email'], verification_link):
            return jsonify({"message": "User registered. Verification link sent to email"}), 201
        else:
            return jsonify({"message": "User registered but failed to send verification email"}), 201

    except mysql.connector.Error as err:
        conn.rollback()
        print("MySQL Error:", err)
        return jsonify({"message": f"Registration failed: {err}"}), 400
    finally:
        cursor.close()
        conn.close()



@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute('SELECT * FROM users WHERE verification_token = %s', (token,))
        user = cursor.fetchone()

        if user:
            cursor.execute('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = %s', (user['id'],))
            conn.commit()
            return jsonify({"message": "Email verified successfully!"}), 200
        else:
            return jsonify({"message": "Invalid verification token"}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch user from the database
        cursor.execute('SELECT * FROM users WHERE email = %s', (data['email'],))
        user = cursor.fetchone()

        if user:
            # Check if the password is correct
            if bcrypt.check_password_hash(user['password'], data['password']):
                # Check if the user's account is verified
                if user['is_verified']:
                    session_token = create_session(user['id'])

                    # Create the response and set session cookie
                    response = make_response(jsonify({"message": "Login successful"}), 200)
                    response.set_cookie('session_token', session_token, max_age=60*60*24*7, samesite='Lax', secure=False, httponly=True)

                    return response
                else:
                    return jsonify({"message": "Account not verified"}), 403
            else:
                return jsonify({"message": "Invalid credentials"}), 401
        else:
            return jsonify({"message": "User not found"}), 404

    except mysql.connector.Error as err:
        # Log and return an error message if there is a MySQL error
        print(f"MySQL Error: {err}")
        return jsonify({"message": "Internal server error"}), 500

    except Exception as e:
        # Catch other general exceptions
        print(f"Error: {e}")
        return jsonify({"message": "An error occurred during login"}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/get-user', methods=['POST'])
def get_user():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        data = request.get_json()
        requested_user_id = data.get('user_id')
        if not requested_user_id:
            return jsonify({"message": "user_id is required"}), 400

        # Fetch user from global_contacts with spam statistics
        cursor.execute('''
            SELECT gc.id, gc.phone_number, gc.name, gc.is_spam, gc.spam_count, gc.spam_likelihood, gc.registered_user_id,
                   (SELECT COUNT(*) FROM spam_reports WHERE phone_number = gc.phone_number) as total_spam_reports,
                   (SELECT COUNT(DISTINCT id) FROM users) as total_users,
                   u.email
            FROM global_contacts gc
            LEFT JOIN users u ON gc.registered_user_id = u.id
            WHERE gc.id = %s
        ''', (requested_user_id,))
        user = cursor.fetchone()

        if user:
            # Check if the global contact is in the user's contacts list
            cursor.execute('''
                SELECT 1 FROM contacts 
                WHERE user_id = %s AND phone_number = %s
            ''', (user_id, user['phone_number']))
            is_in_contacts = cursor.fetchone() is not None

            # Format the response
            response = {
                "id": user['id'],
                "name": user['name'],
                "phone_number": user['phone_number'],
                "is_spam": bool(user['is_spam']),
                "spam_statistics": {
                    "spam_likelihood": float(user['spam_likelihood']),
                    "spam_reports": user['spam_count'],
                    "total_spam_reports": user['total_spam_reports'],
                    "users_reported": f"{user['spam_count']} out of {user['total_users']}"
                }
            }

            # Include email if the contact is in the user's contacts list
            if is_in_contacts and user['email']:
                response["email"] = user['email']

            return jsonify(response), 200
        else:
            return jsonify({"message": "User not found"}), 404
    except mysql.connector.Error as err:
        return jsonify({"message": f"Failed to retrieve user: {err}"}), 500
    finally:
        cursor.close()
        conn.close()
        
@app.route('/add-contact', methods=['POST'])
def add_contact():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    data = request.get_json()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO contacts (user_id, name, phone_number) VALUES (%s, %s, %s)', 
                       (user_id, data['name'], data['phone_number']))

        cursor.execute(
            'INSERT INTO global_contacts (phone_number, name) VALUES (%s, %s) '
            'ON DUPLICATE KEY UPDATE name = VALUES(name)',
            (data['phone_number'], data['name'])
        )

        conn.commit()
        return jsonify({"message": "Contact added"}), 201
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"message": f"Failed to add contact: {err}"}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/mark-spam', methods=['POST'])
def mark_spam():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    data = request.get_json()
    phone_number = data['phone_number']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if user already reported this contact as spam
        cursor.execute('SELECT id FROM spam_reports WHERE user_id = %s AND phone_number = %s', (user_id, phone_number))
        if cursor.fetchone():
            return jsonify({"message": "You have already reported this contact as spam"}), 400

        # Insert spam report
        cursor.execute('INSERT INTO spam_reports (user_id, phone_number) VALUES (%s, %s)', (user_id, phone_number))

        # Update spam count and likelihood
        cursor.execute('UPDATE global_contacts SET is_spam = TRUE, spam_count = spam_count + 1 WHERE phone_number = %s', (phone_number,))
        
        # Get updated spam count
        cursor.execute('SELECT spam_count FROM global_contacts WHERE phone_number = %s', (phone_number,))
        spam_count = cursor.fetchone()[0] or 0

        # Calculate spam likelihood
        cursor.execute('SELECT COUNT(DISTINCT id) FROM users')
        total_system_users = cursor.fetchone()[0] or 1
        cursor.execute('SELECT COUNT(DISTINCT registered_user_id) FROM global_contacts WHERE phone_number = %s', (phone_number,))
        users_with_contact = cursor.fetchone()[0] or 0
        spam_likelihood = (spam_count / users_with_contact) * (users_with_contact / total_system_users) if users_with_contact > 0 else 0
        spam_likelihood = min(max(spam_likelihood, 0), 1)
        cursor.execute('UPDATE global_contacts SET spam_likelihood = %s WHERE phone_number = %s', (spam_likelihood, phone_number))

        conn.commit()
        return jsonify({"message": "Number marked as spam", "spam_likelihood": spam_likelihood}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"message": f"Failed to mark as spam: {err}"}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/unmark-spam', methods=['POST'])
def unmark_spam():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    data = request.get_json()
    phone_number = data['phone_number']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if user reported this contact as spam
        cursor.execute('SELECT id FROM spam_reports WHERE user_id = %s AND phone_number = %s', (user_id, phone_number))
        if not cursor.fetchone():
            return jsonify({"message": "You have not reported this contact as spam"}), 400

        # Delete spam report
        cursor.execute('DELETE FROM spam_reports WHERE user_id = %s AND phone_number = %s', (user_id, phone_number))

        # Update spam count, ensuring it doesn't go below 0
        cursor.execute('UPDATE global_contacts SET spam_count = GREATEST(spam_count - 1, 0) WHERE phone_number = %s', (phone_number,))
        
        # Get updated spam count
        cursor.execute('SELECT spam_count FROM global_contacts WHERE phone_number = %s', (phone_number,))
        spam_count = cursor.fetchone()[0] or 0

        # Calculate spam likelihood
        cursor.execute('SELECT COUNT(DISTINCT id) FROM users')
        total_system_users = cursor.fetchone()[0] or 1
        cursor.execute('SELECT COUNT(DISTINCT registered_user_id) FROM global_contacts WHERE phone_number = %s', (phone_number,))
        users_with_contact = cursor.fetchone()[0] or 0
        spam_likelihood = (spam_count / users_with_contact) * (users_with_contact / total_system_users) if users_with_contact > 0 else 0
        spam_likelihood = min(max(spam_likelihood, 0), 1)

        # Update spam likelihood and is_spam flag
        cursor.execute('UPDATE global_contacts SET spam_likelihood = %s, is_spam = FALSE WHERE phone_number = %s', 
                       (spam_likelihood, phone_number))

        conn.commit()
        return jsonify({"message": "Number unmarked as spam", "spam_likelihood": spam_likelihood}), 200
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"message": f"Failed to unmark as spam: {err}"}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/search', methods=['GET'])
def search():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    query = request.args.get('query', '')
    search_type = request.args.get('type', 'name')  # 'name' or 'phone'

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if search_type == 'name':
            cursor.execute(
                'SELECT name, phone_number, spam_likelihood, registered_user_id '
                'FROM global_contacts '
                'WHERE MATCH(name) AGAINST(%s IN BOOLEAN MODE) '
                'ORDER BY CASE WHEN name LIKE %s THEN 0 ELSE 1 END, '
                'MATCH(name) AGAINST(%s IN BOOLEAN MODE) DESC',
                (f'{query}*', f'{query}%', f'{query}*')
            )
        else:  # phone search
            cursor.execute(
                'SELECT name, phone_number, spam_likelihood, registered_user_id '
                'FROM global_contacts '
                'WHERE phone_number LIKE %s',
                (f'%{query}%',)
            )

        results = cursor.fetchall()

        for result in results:
            if result['registered_user_id']:
                cursor.execute('SELECT email FROM users WHERE id = %s', (result['registered_user_id'],))
                user = cursor.fetchone()
                if user:
                    cursor.execute('SELECT * FROM contacts WHERE user_id = %s AND phone_number = %s', (result['registered_user_id'], user_id))
                    if cursor.fetchone():
                        result['email'] = user['email']

        return jsonify(results), 200
    except mysql.connector.Error as err:
        return jsonify({"message": f"Search failed: {err}"}), 400
    finally:
        cursor.close()
        conn.close()

@app.route('/logout', methods=['POST'])
def logout():
    session_token = request.cookies.get('session_token')
    if session_token:
        r.delete(session_token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE session_token = %s', (session_token,))
        conn.commit()
        cursor.close()
        conn.close()

    response = make_response(jsonify({"message": "Logged out"}), 200)
    response.set_cookie('session_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
    return response

@app.route('/get-global-contacts', methods=['GET'])
def get_global_contacts():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute('SELECT * FROM global_contacts')
        contacts = cursor.fetchall()
        return jsonify(contacts), 200
    except mysql.connector.Error as err:
        return jsonify({"message": f"Failed to retrieve global contacts: {err}"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/get-my-contacts', methods=['POST'])
def get_mycontacts():
    user_id = check_session()
    if not user_id:
        return jsonify({"message": "User not authenticated"}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute('SELECT * FROM contacts WHERE user_id = %s', (user_id,))
        contacts = cursor.fetchall()
        return jsonify(contacts), 200
    except mysql.connector.Error as err:
        return jsonify({"message": f"Failed to retrieve contacts: {err}"}), 500
    finally:
        cursor.close()
        conn.close()



if __name__ == '__main__':
    app.run(host='0.0.0.0')