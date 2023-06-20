from flask import Flask, render_template, flash, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import asc
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, EmailField, FloatField, IntegerField
from wtforms.validators import DataRequired, Length
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = "password"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
app.config['SESSION_TYPE'] = 'shopping_cart'
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


class ItemForm(FlaskForm):
    item = StringField("Item Name: ", validators=[DataRequired()])
    price_pw = FloatField("Price Per Weight: ", validators=[DataRequired()])
    price_pi = FloatField("Price Per Item: ", validators=[DataRequired()])
    short_desc = StringField("Short Description: ", validators=[DataRequired()])
    long_desc = StringField("Long Description: ", validators=[DataRequired()])
    environmental = IntegerField("Environmental: ", validators=[DataRequired()])
    filename = StringField("Filename: ", validators=[DataRequired()])
    submit = SubmitField("Submit")


class Items(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    item = db.Column(db.String(50), unique=True)
    price_pw = db.Column(db.Float(5))
    price_pi = db.Column(db.Float(5))
    short_desc = db.Column(db.String(100))
    long_desc = db.Column(db.String(200))
    environmental = db.Column(db.Integer())
    image = db.Column(db.String(200))
    filename = db.Column(db.String(100))

    def __repr__(self):
        return f"Items('{self.id}', '{self.item}', '{self.price_pw}', '{self.price_pi}', '{self.short_desc}', '{self.long_desc}', '{self.environmental}', '{self.image}'), '{self.filename}')"


class LoginForm(FlaskForm):
    email = EmailField('Email:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Submit')


class PaymentForm(FlaskForm):
    cardnum = StringField("Please enter your 16-digit card number", validators=[DataRequired(), Length(min=16, max=16)])
    cardname = StringField("Please enter your name as it appears on your card", validators=[DataRequired()])
    CVV = StringField("Please enter the CVV number", validators=[DataRequired(), Length(min=3, max=3)])
    submit = SubmitField("Pay")

@lm.user_loader
def load_user(id):
    return UserLogin.query.get(int(id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = LoginForm()
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
            return redirect(url_for('index'))
        flash(f"There is already a user with the email address {form.email.data}. Please try logging in or using a different email address.")
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = UserLogin.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash("Credentials are incorrect. Please try again.")
            return redirect(url_for('login'))
        login_user(user, form.remember_me.data)
        flash("You are now logged in.")
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    sortBy = None
    items = Items.query.all()
    if request.method == "POST":
        sortBy = request.form['sortby']
        items = Items.query.order_by(asc(sortBy)).all()
    return render_template('index.html', items=items)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

@app.route('/items', methods = ['GET', 'POST'])
@login_required
def items():
    if current_user.id == 1:    
        id = None
        item = None
        price_pw = None
        price_pi = None
        short_desc = None
        long_desc = None
        environmental = None
        filename = None
        form = ItemForm()
        if form.validate_on_submit():
            item = form.item.data
            form.item.data = ''
            price_pw = form.price_pw.data
            form.price_pw.data = ''
            price_pi = form.price_pi.data
            form.price_pi.data = ''
            short_desc = form.short_desc.data
            form.short_desc.data = ''
            long_desc = form.long_desc.data
            form.long_desc.data = ''
            environmental = form.environmental.data
            form.environmental.data = ''
            filename = form.filename.data
            form.filename.data = ''
            db.session.add(Items(id=id, item=item, price_pw=price_pw, price_pi=price_pi,
                                    short_desc=short_desc, long_desc=long_desc,
                                    environmental=environmental, filename=filename))
            db.session.commit()
        items = Items.query.all()
        return render_template('items.html', form=form, id=id, item=item, price_pw=price_pw, 
                                price_pi=price_pi, short_desc=short_desc, long_desc=long_desc, 
                                environmental=environmental, filename=filename, items=items)
    flash("You do not have access to this page.")
    return redirect(url_for('index'))
    
@app.route('/itempage/<string:id>')
def itempage(id):
    item = Items.query.get_or_404(id)
    return render_template('itempage.html', item=item)

@app.route('/cart', methods=['GET', 'POST'])
def cart():
    total = 0
    cart = session.get('cart', [])
    for item in cart:
        price = cart[item]['price']
        quantity = cart[item]['quantity']
        total += float(price) * int(quantity)
    return render_template("cart.html", cart=cart, total=round(total, 2))

@app.route('/add_to_cart/<int:id>', methods=["GET", "POST"])
def add_to_cart(id):
    item = Items.query.get_or_404(id)
    price = request.form['price']
    type = request.form['type']
    comb = str(item.id) + type
    if 'cart' not in session:
        session['cart'] = {}
    cart = session.get('cart', [])
    if comb in cart:
            cart[comb]['quantity'] += 1
    else:
        cart[comb] = {'item': item.item, 'price': price, 'quantity': 1, 'type': type}
    session.modified = True
    flash(item.item + " added to cart.")
    return redirect(url_for('index'))

@app.route('/clear_cart')
def clear_cart():
    cart = session.get('cart', [])
    if len(cart) == 0:
        flash("There is nothing in your cart. Please add something before clearing.")
        return redirect(url_for('index'))
    session.clear()
    flash("You cleared your shopping cart.")
    return redirect(url_for('cart'))

@app.route('/remove_item/<string:id>')
def remove_item(id):
    id_num = id.split("|")[0]
    item = Items.query.get_or_404(id_num)
    cart = session.get('cart', [])
    if cart[id]['quantity'] > 1:
        cart[id]['quantity'] -= 1
    else:
        cart.pop(id)
    removed = item.item
    flash("You removed " + removed + ".")
    return redirect(url_for('cart'))

@app.route('/payment/<total>', methods=['GET', 'POST'])
def payment(total):
    payment = False
    form = PaymentForm()
    if form.validate_on_submit():
        payment = True
        form.cardnum.data = ''
        form.cardname.data = ''
        form.CVV.data = ''
        flash("Payment Was Successful!")
    return render_template("payment.html", payment=payment, form=form, total=total)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)