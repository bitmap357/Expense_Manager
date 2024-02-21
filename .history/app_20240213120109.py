from flask import Flask, render_template, request, redirect, url_for, Blueprint, session, abort
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
from flask_bcrypt import Bcrypt
import pathlib
from google.auth.transport.requests import Request
import requests
import os
# from flask_migrate import Migrate
# from .models import Expense
# from . import db
# import models
# db = models.db
# from .models import db, Expense

# app = Blueprint('app', __name__)
project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(
    os.path.join(project_dir, "mydatabase.db")
)



app = Flask(__name__)
sess = Session()
app.config["SQLALCHEMY_DATABASE_URI"] = database_file
db = SQLAlchemy(app)
# db.init_app(app)
bcrypt = Bcrypt(app)
# app.config['SECRET_KEY'] = 'thisismysecretkey'


# os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

GOOGLE_CLIENT_ID = "828960771939-bu24ngd36lpkt5hb5dpf7i3h46cu0aad.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# migrate = Migrate(app, db)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
    return db.session.get(User, int(user_id))


# class Config(Config):
#     # Other configurations...
#     MAIL_SERVER = 'your_smtp_server'
#     MAIL_PORT = 587
#     MAIL_USE_TLS = True
#     MAIL_USERNAME = 'your_email_username'
#     MAIL_PASSWORD = 'your_email_password'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    google_id = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(50), nullable=False)
    expensename = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)

# @app.route('/#')
# def index():
#     return 'App Blueprint'

@app.route('/')
@login_required
def add():
    return render_template('add.html')

@app.route('/delete/<int:id>')
def delete(id):
    expense = Expense.query.filter_by(id=id).first()
    db.session.delete(expense)
    db.session.commit()
    return redirect('/expenses')
    
@app.route('/updateexpense/<int:id>')
def updateexpense(id):
    expense = Expense.query.filter_by(id=id).first()
    return render_template('updateexpense.html', expense=expense)

@app.route('/edit', methods=['POST'])
def edit():
    id = request.form['id']
    date = request.form['date']
    expensename = request.form['expensename']
    amount = request.form['amount']
    category = request.form['category']
    
    expense = Expense.query.filter_by(id=id).first()
    expense.date = date
    expense.expensename = expensename
    expense.amount = amount
    expense.category = category
    
    db.session.commit()
    return redirect("/expenses")

    
@app.route('/expenses')
@login_required
def expenses():
    expenses = Expense.query.all()
    total = 0
    t_business = 0
    t_other = 0
    t_food = 0
    t_entertainment = 0
    for expense in expenses:
        total += expense.amount
        if expense.category == 'Business':
            t_business +=expense.amount
        elif expense.category == 'Other':
            t_other +=expense.amount
        elif expense.category == 'Food':
            t_food +=expense.amount
        elif expense.category == 'Entertainment':
            t_entertainment +=expense.amount
    return render_template(
        'expenses.html', 
        expenses=expenses, 
        total=total, 
        t_entertainment=t_entertainment, 
        t_food=t_food, 
        t_business=t_business, 
        t_other=t_other)

@app.route('/addexpense', methods=['POST'])
@login_required
def addexpense():
    date = request.form['date']
    expensename = request.form['expensename']
    amount = request.form['amount']
    category = request.form['category']
    print(date + expensename + amount + category)
    expense = Expense(date=date, expensename=expensename, amount=amount, category=category)
    db.session.add(expense)
    db.session.commit()
    return redirect("/expenses")

@app.route('/addview', methods=['GET', 'POST'])
@login_required
def addview():
    if request.method == 'GET':
        expenses = Expense.query.all()
        total = 0
        t_business = 0
        t_other = 0
        t_food = 0
        t_entertainment = 0
        for expense in expenses:
            total += expense.amount
            if expense.category == 'Business':
                t_business +=expense.amount
            elif expense.category == 'Other':
                t_other +=expense.amount
            elif expense.category == 'Food':
                t_food +=expense.amount
            elif expense.category == 'Entertainment':
                t_entertainment +=expense.amount
    elif request.method == 'POST':
        date = request.form['date']
        expensename = request.form['expensename']
        amount = request.form['amount']
        category = request.form['category']
        print(date + expensename + amount + category)
        expense = Expense(date=date, expensename=expensename, amount=amount, category=category)
        db.session.add(expense)
        db.session.commit()
        return redirect("/addview")

    return render_template(
    'addview.html', 
    expenses=expenses, 
    total=total, 
    t_entertainment=t_entertainment, 
    t_food=t_food, 
    t_business=t_business, 
    t_other=t_other)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('addview'))
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/google')
@app.route('/google')
def login_with_google():
    # authorization_url, state = flow.authorization_url()
    authorization_url, state = flow.authorization_url(
    access_type='offline',
    prompt='consent'
    )
    print("Authorization URL:", authorization_url)
    app.logger.info("Authorization URL: %s", authorization_url)
    # authorization_url, state = flow.authorization_url()
    authorization_url, state = flow.authorization_url(
    access_type='offline',
    prompt='consent'
    )
    print("Authorization URL:", authorization_url)
    app.logger.info("Authorization URL: %s", authorization_url)
    session["state"] = state
    return redirect(authorization_url)


# @app.route('/callback')
# def google_callback():
#     # code = request.args.get('code')
#     # flow.fetch_token(code=code)
#     # id_info = verify_google_token(flow.credentials.id_token)
#     if id_info:
#         user = User.query.filter_by(google_id=id_info['sub']).first()
#         if not user:
#             # Create new user
#             user = User(google_id=id_info['sub'])
#             db.session.add(user)
#             db.session.commit()
#         login_user(user)
#         return redirect(url_for('addview'))
#     else:
#         return 'Failed to authenticate with Google.', 401

# @app.route("/callback")
# def callback():
    # flow.fetch_token(authorization_response=request.url)
    # print(request.args)
    # code = request.args.get('code')
    # app.logger.info('Authorization code: %s', code)
    # flow.fetch_token(authorization_response=request.url)
    
# @app.route('/callback')
# def google_callback():
#     # code = request.args.get('code')
#     # flow.fetch_token(code=code)
#     # id_info = verify_google_token(flow.credentials.id_token)
#     if id_info:
#         user = User.query.filter_by(google_id=id_info['sub']).first()
#         if not user:
#             # Create new user
#             user = User(google_id=id_info['sub'])
#             db.session.add(user)
#             db.session.commit()
#         login_user(user)
#         return redirect(url_for('addview'))
#     else:
#         return 'Failed to authenticate with Google.', 401


@app.route("/callback")
def callback():
    # flow.fetch_token(authorization_response=request.url)
    # print(request.args)
    # code = request.args.get('code')
    # app.logger.info('Authorization code: %s', code)
    # flow.fetch_token(authorization_response=request.url)
    
    code = request.args.get('code')
    app.logger.info('Authorization code: %s', code)
    
    # session_state = session.get("state")
    # if session_state is None or session_state != request.args.get("state"):
    #     abort(500)
    if not session["state"] == request.args["state"]:
        app.logger.error('State mismatch or missing')
        abort(500)  # State does not match!
    
    token_url, _ = flow.authorization_url()
    token_url = token_url.replace('response_type=code', 'response_type=token')
    token_url = token_url.replace('access_type=offline', '')  # Remove offline access type if present
    token_url += '&code=' + code

    response = requests.post(token_url)
    print("Token endpoint response content:", response.content)  # Print response content for debugging
    try:
        token_response = response.json()
    except ValueError:
        abort(500)
        
        
    flow.fetch_token(code=code)
    
    credentials = flow.credentials
    # request_session = request.session()
    cached_session = cachecontrol.CacheControl(session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/addview")
    
    # credentials = flow.credentials
    # request_session = request.session()
    # cached_session = cachecontrol.CacheControl(request_session)
    # token_request = google.auth.transport.requests.Request(session=cached_session)

    # id_info = id_token.verify_oauth2_token(
    #     id_token=credentials._id_token,
    #     request=token_request,
    #     audience=GOOGLE_CLIENT_ID
    # )

    # session["google_id"] = id_info.get("sub")
    # session["name"] = id_info.get("name")
    # return redirect("/addview")



if __name__ == '__main__':
    app.secret_key = 'thisismysecretkey'
    app.config['SESSION_TYPE'] = 'filesystem'
    sess.init_app(app)
    app.run(debug=True)