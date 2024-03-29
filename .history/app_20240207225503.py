from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os

project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(
    os.path.join(project_dir, "mydatabase.db")
)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = database_file
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'thisismysecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
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

    

@app.route('/')
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
                return redirect(url_for('dashboard'))
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



if __name__ == '__main__':
    app.run(debug=True)