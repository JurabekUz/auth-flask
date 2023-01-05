from flask import Flask, redirect, render_template,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_login import LoginManager
from flask_login import login_user,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt
app = Flask(__name__)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SECRET_KEY'] = 'secretkeyauthappaaaa'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "Login"

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20),nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Pasword"})
    sumbit = SubmitField('Register')

    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username = username.data).first()
        if existing_user_username:
            raise ValidationError("That username e xists. Please choose a different one")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Pasword"})
    sumbit = SubmitField('Login')

db.create_all()
db.session.commit()

@app.route('/')
def Home():
    return render_template("home.html")

@app.route('/login', methods=['POST','GET'])
def Login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('Dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST','GET'])
@login_required
def Logout():
    logout_user()
    return redirect(url_for('Login'))

@app.route('/dashboard', methods=['POST','GET'])
@login_required
def Dashboard():
    return render_template('dashboard.html')

@app.route('/register', methods=['POST','GET'])
def Register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user=User(name=form.name.data,username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('Login'))
    return render_template('register.html',form=form)


if __name__=='__main__':
    app.run(debug=True)