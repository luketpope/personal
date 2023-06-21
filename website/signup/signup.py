from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import SubmitField, PasswordField, BooleanField, EmailField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin

app = Flask(__name__)
app.config['SECRET_KEY'] = "password"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = 'login'

class UserLogin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True, unique=True)
    password_hash = db.Column(db.String(64))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def register(email, password):
        email = UserLogin(email=email)
        email.set_password(password)
        db.session.add(email)
        db.session.commit()
        return email
    
    def __repr__(self):
        return f"<User {self.email})>"
    
class LoginForm(FlaskForm):
    email = EmailField('Email:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Submit')

@lm.user_loader
def load_user(id):
    return UserLogin.query.get(int(id))

@app.route('/', methods=['GET', 'POST'])
def signup():
    form = LoginForm()
    database = UserLogin.query.all()
    email = None
    password = None
    remember_me = False
    if form.validate_on_submit():
        user = UserLogin.query.filter_by(email=form.email.data).first()
        if user is None:
            email = form.email.data
            form.email.data = ''
            password = form.password.data
            form.password.data = ''
            remember_me = form.remember_me.data
            form.remember_me.data = False
            UserLogin.register(email, password)
            flash(f"You are now successfully signed up with the email address {email}.")
            return redirect(url_for('signup'))
        flash(f"There is already a user with the email address {form.email.data}. Please try logging in or using a different email address.")
        return redirect(url_for('signup'))
    return render_template('signup.html', form=form, database=database)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)