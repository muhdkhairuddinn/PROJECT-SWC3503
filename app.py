from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import pyotp
import qrcode  # Import the qrcode library
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import logging
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)

DATABASE = 'members.db'

# Configure the logging
logging.basicConfig(filename='gym_app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Simple user store for staff and members (no security library)
USERS = {
    "staff": {"password": "staffpass", "role": "staff"},
    "member": {"password": "memberpass", "role": "member"},
    "pakkarim": {"password": "karim", "role": "staff"}
}

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Input Validation Function
def validate_input(input_str):
    """Validate input to allow only alphanumeric characters and a few safe symbols."""
    if re.match("^[a-zA-Z0-9_@.-]+$", input_str):  # Only allows alphanumeric, _, @, ., -
        return True
    return False

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                membership_status TEXT NOT NULL
                                    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY,
                class_name TEXT NOT NULL,
                class_time TEXT NOT NULL
                                    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                member_id INTEGER,
                class_id INTEGER,
                FOREIGN KEY (member_id) REFERENCES members (id),
                FOREIGN KEY (class_id) REFERENCES classes (id)
                                    )''')
    db.commit()

# Home Route (Login) with Logging
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate the input fields
        if not validate_input(username) or not validate_input(password):
            logging.warning(f"Invalid characters detected in username or password input: {username}")
            return "Invalid input detected. Only certain characters are allowed.", 400
        
        # Check if the user is in the in-memory dictionary
        if username in USERS:
            user_data = USERS[username]
            if user_data['password'] == password:
                session['user'] = username
                session['role'] = user_data['role']
                
                # Log successful login from in-memory dictionary
                logging.info(f"Successful login for in-memory user: {username} with role: {user_data['role']}")
                
                return redirect(url_for('generate_otp'))
            else:
                # Log incorrect password attempt for in-memory user
                logging.warning(f"Failed login attempt for in-memory user: {username} (incorrect password)")
                return "Login Failed! Incorrect password."
        
        # If not in the in-memory dictionary, check the database
        db = get_db()  # Get a connection to the database
        db.row_factory = sqlite3.Row  # Set row factory to return dictionaries
        user = db.execute("SELECT * FROM members WHERE name = ?", (username,)).fetchone()
        db.close()

        # Check if user exists in the database
        if user is None:
            # Log failed login attempt for non-existent database user
            logging.warning(f"Failed login attempt for non-existent database user: {username}")
            return "Login Failed! User does not exist."

        # Validate the password against the hashed password in the database
        if check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['membership_status']  # Assuming membership_status is the correct role attribute
            
            # Log successful login from database
            logging.info(f"Successful login for database user: {username} with role: {user['membership_status']}")
            
            return redirect(url_for('generate_otp'))
        else:
            # Log incorrect password attempt for database user
            logging.warning(f"Failed login attempt for database user: {username} (incorrect password)")
            return "Login Failed! Incorrect password."
        
    return render_template('login.html')



# Function to retrieve user's OTP secret (replace with your own logic)
def get_user_secret(username):
    # Simulating a secret for a user (In real use, retrieve from your database)
    return 'JBSWY3DPEHPK3PXP'  # Replace with a way to fetch the secret for the user

# Generate OTP and QR Code
@app.route('/generate_otp', methods=['GET'])
def generate_otp():
    user_id = session.get('user')  # Retrieve the logged-in user
    if user_id is None:
        return redirect(url_for('login'))  # Redirect if user is not logged in

    secret = get_user_secret(user_id)  # Retrieve OTP secret for user
    if secret is None:
        logging.error(f"Error: OTP secret not found for user {user_id}")
        return "Error: OTP secret not found", 400
    
    # Log initiation of OTP generation
    logging.info(f"Initiated OTP generation for user: {user_id}")

    # Generate the QR Code for the authenticator app
    qr = qrcode.make(f'otpauth://totp/{user_id}?secret={secret}&issuer=GymManagement')
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')  # Encode QR code to base64 for rendering

    # Log successful QR code generation
    logging.info(f"Generated 2FA QR code for user: {user_id}")

    return render_template('otp_display.html', qr_code=qr_code)  # Remove `otp=otp` here


# Verify OTP
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_id = session.get('user')  # Retrieve the logged-in user
    if user_id is None:
        return redirect(url_for('login'))  # Redirect if user is not logged in

    secret = get_user_secret(user_id)  # Retrieve OTP secret for user
    if secret is None:
        logging.error(f"Error: OTP secret not found for user {user_id}")
        return "Error: OTP secret not found", 400

    entered_otp = request.form['otp']  # Get the OTP entered by the user
    totp = pyotp.TOTP(secret)

    if totp.verify(entered_otp):
        # Log successful OTP verification
        logging.info(f"Successful 2FA verification for user: {user_id}")
        return redirect(url_for('dashboard'))  # Redirect to dashboard on successful verification
    
    else:
        # Log failed OTP verification attempt
        logging.warning(f"Failed 2FA verification attempt for user: {user_id}")
        return "Invalid OTP. Please try again.", 400

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    return render_template('add_member.html')

# View specific member class
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# New Route for Registering a Member (Restricted to Staff)
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return "Access denied: Staff only."  # Deny access for non-staff users
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        password = request.form['password']  # Get password from the form
        
        # Hash the password after retrieving it
        hashed_password = generate_password_hash(password)

        db = get_db()
        db.execute("INSERT INTO members (name, password, membership_status) VALUES (?, ?, ?)", (name, hashed_password, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Delete member from the database
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    
    # Also delete any classes associated with the member in the member_classes table
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    print("Starting Flask app at http://127.0.0.1:5000")  # Add this line
    app.run(host='127.0.0.1', port=5000, debug=True)

