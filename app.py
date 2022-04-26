from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret'
bcrypt = Bcrypt(app)

login_menager = LoginManager()
login_menager.init_app(app)
login_menager.login_view = 'login'

@login_menager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    isAdmin = db.Column(db.Boolean, default=True)



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
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
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

#HOME ROUTE
@app.route('/')
def home():
    return render_template('home.html')

#LOGIN ROUTE
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form = form)

#DASHBOARD ROUTE
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

#LOGOUT ROUTE
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

#ADMIN ROUTE
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    users = User.query.all()
    if current_user.isAdmin:
        return render_template('admin.html', users = users)
    else:
        return "You are not an admin"

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

#USER EDIT ROUTE
@app.route('/edit/<int:id>', methods = ['POST', 'GET'])
@login_required
def edit(id):
    form = EditForm()
    user = User.query.get(id)
    if current_user.id == id:
        return render_template('edit.html', user = user, form = form)
    else:
        return "You can only edit your own profile"
   
#ADMIN EDIT ROUTE
@app.route('/admin/edit/<int:id>', methods = ['POST', 'GET'])
@login_required
def admin_edit(id):
    form = EditForm()
    user = User.query.get(id)
    if current_user.isAdmin:
        return render_template('admin_edit.html', user = user, form = form)
    else:
        return "You dont have permission to edit this user"

if __name__ == '__main__':
    app.run(debug=True)