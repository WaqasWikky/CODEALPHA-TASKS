from flask import Flask, render_template, request, redirect, url_for, session
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_principal import Principal, Permission, RoleNeed
import os
import hashlib

# Import the custom secure_filename function
from custom_werkzeug_utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Securely generate a secret key for Flask sessions

# Configuration for file uploads
photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
configure_uploads(app, photos)

# Configuration for Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration for Flask-Principal
principal = Principal(app)
admin_permission = Permission(RoleNeed('admin'))

# Dummy database of users
class User(UserMixin):
    def __init__(self, username, password, is_admin=False):
        self.id = username
        self.password = hashlib.sha256(password.encode()).hexdigest()
        self.is_admin = is_admin

users = {'admin': User('admin', 'adminpassword', is_admin=True)}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user.password == hashlib.sha256(password.encode()).hexdigest():
            login_user(user)
            return redirect(url_for('upload'))
    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST' and 'photo' in request.files:
        filename = secure_filename(request.files['photo'].filename)
        request.files['photo'].save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename))
        return redirect(url_for('uploaded_file', filename=filename))
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return render_template('uploaded_file.html', filename=filename)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
