from flask import Flask, flash, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField, SubmitField, BooleanField, FileField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Length, Email, ValidationError, NumberRange
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = set(['jpg'])

app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret'
#app.config["UPLOAD_FOLDER"] = "static/img"
bcrypt = Bcrypt(app)

login_menager = LoginManager()
login_menager.init_app(app)
login_menager.login_view = 'login'

@login_menager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False , default=False)
    login_counter = db.Column(db.Integer, nullable=False , default=0)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50), unique=True, nullable=False)
    author = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    num_pages = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=50)])
    surname = StringField('Surname', validators=[InputRequired(), Length(min=2, max=50)])
    isAdmin = BooleanField('Admin')
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')

class EditForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=50)])
    surname = StringField('Surname', validators=[InputRequired(), Length(min=2, max=50)])
    submit = SubmitField('Edit')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('This username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('This email is taken. Please choose a different one.')

class PasswordChangeForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[InputRequired(), Length(min=8, max=20)])
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=20)])
    submit = SubmitField('Change')

class BookForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=2, max=50)])
    author = StringField('Author', validators=[InputRequired(), Length(min=2, max=50)])
    year = IntegerField('Year', validators=[InputRequired(), NumberRange(min=1, max=2200)])
    genre = StringField('Genre', validators=[InputRequired(), Length(min=2, max=50)])
    num_pages = IntegerField('Number of pages', validators=[InputRequired(), NumberRange(min=1, max=2000)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(min=2, max=500)])
    submit = SubmitField('Submit')

#HOME ROUTE
@app.route('/')
def home():
    return render_template('home.html')


#!!!!!!!!!!!!!!!!!!!!
#USER STUFF
#!!!!!!!!!!!!!!!!!!!!
#LOGIN ROUTE
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                user.login_counter += 1
                db.session.commit()
                return redirect(url_for('dashboard'))
    return render_template('login.html', form = form)

#LOGOUT ROUTE
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

#REGISTER ROUTE
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, name=form.name.data, surname=form.surname.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form = form)

#CHANGE PASSWORD ROUTE
@app.route('/change_password/<int:id>', methods = ['POST', 'GET'])
@login_required
def change_password(id):
    form = PasswordChangeForm()
    user = User.query.get(id)
    if ((current_user.id == id) or current_user.isAdmin):
        if form.is_submitted():
            if bcrypt.check_password_hash(user.password, form.old_password.data):
                user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                db.session.commit()
                logout_user()
        return render_template('change_password.html', user = user, form = form)
    else:
        return "You can only change your own password"

#USER EDIT ROUTE
@app.route('/edit_user/<int:id>', methods = ['POST', 'GET'])
@login_required
def edit(id):
    form = EditForm()
    user = User.query.get(id)
    if ((current_user.id == id) or current_user.isAdmin):
        if form.is_submitted():
            user.username = form.username.data
            user.email = form.email.data
            user.name = form.name.data
            user.surname = form.surname.data
            db.session.commit()
            return redirect(url_for('dashboard'))
        return render_template('edit.html', form = form, user = user)

        
    else:
        return "You can only edit your own profile"

#USER DELETE ROUTE
@app.route('/delete_user/<int:id>', methods = ['POST', 'GET'])
@login_required
def delete(id):
    user = User.query.get(id)
    if ((current_user.id == id) or current_user.isAdmin):
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('admin'))
    else:
        return "You can only delete your own profile"

  
#!!!!!!!!!!!!!!!!!!!!!!
#ADMIN STUFF
#!!!!!!!!!!!!!!!!!!!!!!

#ADMIN DASHBOARD ROUTE
@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.isAdmin:
        return render_template('admin_dashboard.html')
    else:
        return "You are not an admin"

#ADMIN USER ROUTE
@app.route('/admin_user', methods=['GET', 'POST'])
@login_required
def admin_user():
    if current_user.isAdmin:
        users = User.query.all()
        return render_template('admin_user.html', users = users)
    else:
        return "You are not an admin"

#ADMIN BOOK ROUTE
@app.route('/admin_book', methods=['GET', 'POST'])
@login_required
def admin_book():
    if current_user.isAdmin:
        books = Book.query.all()
        return render_template('admin_book.html', books = books)
    else:
        return "You are not an admin"
   
#!!!!!!!!!!!!!!!!!!!!
#BOOK STUFF
#!!!!!!!!!!!!!!!!!!!!

#BOOK ADD ROUTE
@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    form = BookForm()
    if form.validate_on_submit():
        book = Book(title=form.title.data, author=form.author.data, year=form.year.data, genre=form.genre.data, num_pages=form.num_pages.data, description=form.description.data)
        db.session.add(book)
        db.session.commit()
        return redirect(url_for('admin_book'))
    return render_template('add_book.html', form = form)


#BOOK DELETE ROUTE
@app.route('/delete_book/<int:id>', methods = ['POST', 'GET'])
@login_required
def delete_book(id):
    book = Book.query.get(id)
    if current_user.isAdmin:
        db.session.delete(book)
        db.session.commit()
        return redirect(url_for('admin_book'))
    else:
        return "You don't have permission to delete this book"

#BOOK EDIT ROUTE
@app.route('/book_edit/<int:id>', methods = ['POST', 'GET'])
@login_required
def book_edit(id):
    book = Book.query.get(id)
    if current_user.isAdmin:
        form = BookForm()
        if form.is_submitted():
            book.title = form.title.data
            book.author = form.author.data
            book.year = form.year.data
            book.genre = form.genre.data
            book.num_pages = form.num_pages.data
            book.description = form.description.data
            db.session.commit()
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

#!!!!!!!!!!!!!!!!!!!!
#OTHER STUFF
#!!!!!!!!!!!!!!!!!!!!

#TOP USER LOGIN ROUTE
@app.route('/top_user_login', methods = ['POST', 'GET'])
def top_user_login():
    users = User.query.order_by(User.login_counter.desc()).limit(3)
    return render_template('top_user_login.html', users = users)

#DASHBOARD ROUTE
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = current_user
    return render_template('dashboard.html', user = user )



if __name__ == '__main__':
    app.run(debug=True)




