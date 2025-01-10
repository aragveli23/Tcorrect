from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from textblob import TextBlob
import os

# Initialize Flask App
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')  # Use environment variable for security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# User model for database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # Hashed password

# Helper function to check if user is logged in
def is_logged_in():
    return 'user_id' in session

# Route for homepage
@app.route('/')
def home():
    return render_template('home.html')

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        flash('Login Unsuccessful. Please check your username and password', 'danger')

    return render_template('login.html')

# Route for logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Route for register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Try a different one.', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# Route for dashboard (after login)
@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('dashboard.html', name=session.get('username'))

# Route for text correction
@app.route('/correct', methods=['GET', 'POST'])
def correct_text():
    if not is_logged_in():
        return redirect(url_for('login'))
    if request.method == 'POST':
        text = request.form['text']
        blob = TextBlob(text)
        corrected_text = blob.correct()
        return render_template('correct.html', original=text, corrected=str(corrected_text))
    return render_template('correct.html', original=None, corrected=None)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create the database tables if they don't exist
    app.run(debug=True)
