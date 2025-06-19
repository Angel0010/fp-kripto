from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import hashlib
import bcrypt
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secret-key'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

users = {}  # Simpan hash password
file_hashes = {}  # Simpan hash file

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        users[username] = hashed
        flash('Berhasil registrasi!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        if username in users and bcrypt.checkpw(password, users[username]):
            session['user'] = username
            flash('Login berhasil')
            return redirect(url_for('dashboard'))
        else:
            flash('Login gagal')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/hash_file', methods=['GET', 'POST'])
def hash_file():
    if request.method == 'POST':
        f = request.files['file']
        if f:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
            f.save(filepath)
            with open(filepath, 'rb') as file:
                file_data = file.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
                file_hashes[f.filename] = file_hash
            return render_template('hash_file.html', filehash=file_hash, filename=f.filename)
    return render_template('hash_file.html')

@app.route('/check_file', methods=['GET', 'POST'])
def check_file():
    result = None
    if request.method == 'POST':
        f = request.files['file']
        if f and f.filename in file_hashes:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
            f.save(filepath)
            with open(filepath, 'rb') as file:
                file_data = file.read()
                new_hash = hashlib.sha256(file_data).hexdigest()
                original_hash = file_hashes[f.filename]
                result = (new_hash == original_hash)
            return render_template('check_file.html', result=result, filename=f.filename, new_hash=new_hash, original_hash=original_hash)
    return render_template('check_file.html')

if __name__ == '__main__':
    app.run(debug=True)