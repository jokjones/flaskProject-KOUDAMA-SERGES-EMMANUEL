from flask import Flask, render_template, request, flash, url_for, session, redirect
from flask_sqlalchemy import SQLAlchemy
import re

from urllib.parse import quote_plus
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

password=quote_plus('serges11')
conne='postgres://postgres:()@localhost:5432/formular'.format(password)
app.config['SQLALCHEMY_DATABASE_URI']=conne
app.config['SQLALCHEMY_TRACK_MODIFICATION']=False

db=SQLAlchemy(app)

class Users(db.Model):
    id = db.column(db.Integer, primary_key=True)
    fullname = db.column(db.String(250), unique=True, nullable=False)
    username = db.column(db.String(50), nullable=False)
    password = db.column(db.String(80), nullable=False)
    email = db.column(db.String(120), unique=True, nullable=False)


db.create_all()


@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/register', method=['GET', 'POST'])
def register():

    if request.method == 'POSt' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        _hashed_password = generate_password_hash(password)
        cursor = conne.cursor(cursor_factory=SQLAlchemy)
        cursor.execute('SELECT * FROM users WHERE username= %s', (username,))
        account = cursor.fetchone()
        print(account)
        if account:
            flash('account already exists!')
        elif not re.match(r'[^@]+@[^@]+\[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            cursor.execute("INSERT INTO users (fullname,username,password,email)VALUES (%s,%s,%s,%s)",
                           (fullname, username, _hashed_password, email))
            conne.commit
            flash('you have successfully registered')
    elif request.method == 'POST':
        flash('please fill out the form!')
    return render_template('register.html')


@app.route('/login/', method=['GET', 'POST'])
def login():
    cursor = conne.cursor(cursor_factory=SQLAlchemy)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        print(password)
        cursor.execute('SELECT*FROM username = %s', (username,))
        account = cursor.fetchone()

        if account:
            password_rs = account['password']
            print(password_rs)

            if check_password_hash(password_rs, password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                return redirect(url_for('home'))
        else:
            flash('incorrect username/password')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users WHERE id= %s', [session['id']])
        account = cursor.fetchone()
        return render_template('profile.html', account=account)

    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
