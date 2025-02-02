from pydoc import text
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, auth, firestore
import requests as req
import logging
import os
import jwt

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Check for required environment variables
required_env_vars = ['PUBLIC_KEY', 'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']
for var in required_env_vars:
    if not os.environ.get(var):
        raise ValueError(f"The {var} environment variable is not set.")

# Retrieve environment variables
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = 'https://grc-project.onrender.com/callback'

# Initialize Firebase Admin SDK
cred_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)


# Initialize Firestore DB
db = firestore.client()

def verify_jwt_token(token):
    try:
        decoded_token = jwt.decode(token, PUBLIC_KEY, algorithms=["ES256"])
        print(f"Decoded JWT: {decoded_token}")  # Debugging
        return decoded_token
    except jwt.InvalidTokenError as e:
        print(f"JWT verification failed: {e}")  # Debugging
        return None

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)




def verify_firebase_token(token):
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token
    except firebase_admin.auth.InvalidIdTokenError:
        return None
    except firebase_admin.auth.ExpiredIdTokenError:
        return None
    except firebase_admin.auth.RevokedIdTokenError:
        return None
    except firebase_admin.auth.CertificateFetchError:
        return None

@app.route('/login')
def login():
    print(f"Using REDIRECT_URI: {REDIRECT_URI}")
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/auth?"
        "response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        "scope=openid%20email%20profile&"
        "access_type=offline"
    )
    return redirect(google_auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        flash('Authorization failed.')
        return redirect(url_for('index'))

    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    token_response = req.post(token_url, data=token_data)
    token_json = token_response.json()
    id_token_str = token_json.get('id_token')

    try:
        idinfo = id_token.verify_oauth2_token(id_token_str, google_requests.Request(), CLIENT_ID)
        user_id = idinfo['sub']
        user = User(user_id)
        login_user(user)
        return redirect(url_for('index'))
    except ValueError as e:
        logging.error(f"Token verification failed: {e}")
        flash('Invalid token')
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        submissions = db.collection('submissions').stream()
        rows = [(submission.to_dict()['text'], submission.to_dict()['timestamp'], submission.to_dict().get('is_jwt', False)) for submission in submissions]
    else:
        rows = []
    return render_template('index.html', table_data=rows)

@app.route('/submit', methods=['POST'])
@login_required
def submit():
    text = request.form['text']  # Get the text input
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Generate current timestamp
    user_id = current_user.id  # Get the current user's ID
    is_jwt = False  # Default to False

    # Check if the input is potentially a JWT (contains 2 dots)
    if text.count('.') == 2:
        try:
            # Attempt to verify the JWT
            decoded_token = verify_jwt_token(text)
            if decoded_token:
                is_jwt = True  # Mark as a valid JWT if verification succeeds
                print(f"JWT successfully verified: {decoded_token}")  # Debugging
            else:
                print("JWT verification failed")  # Debugging
        except Exception as e:
            print(f"Error during JWT verification: {e}")  # Debugging

    logging.debug(f"Submitting text: {text}, timestamp: {timestamp}, user_id: {user_id}, is_jwt: {is_jwt}")

    # Save the submission to Firestore
    try:
        doc_ref = db.collection('submissions').document()  # Create a new document
        doc_ref.set({
            'text': text,
            'timestamp': timestamp,
            'user_id': user_id,
            'is_jwt': is_jwt  # Save the is_jwt flag
        })
        logging.debug("Submission saved successfully")
    except Exception as e:
        logging.error(f"Error saving submission: {e}")
        flash('Error during submission')  # Inform the user of the error

    return redirect(url_for('index'))  # Redirect back to the main page



@app.route('/protected')
def protected():
    token = request.headers.get('Authorization').split()[1]
    payload = verify_firebase_token(token)
    if payload:
        return "JWT is valid"
    else:
        return "Invalid JWT", 401

@app.route('/ping')
def ping():
    return 'pong', 200

print(f"REDIRECT_URI used: {REDIRECT_URI}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True, port=5000)