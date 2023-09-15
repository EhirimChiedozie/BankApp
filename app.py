from flask import Flask, render_template, url_for, flash, redirect, request, Response
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired,Length, EqualTo, ValidationError
from sqlalchemy import Column, String, Integer,  Boolean,create_engine, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from itsdangerous import TimedJSONWebSignatureSerializer as serializer
from email.message import EmailMessage, Message
import ssl
import smtplib
from flask_mail import Mail
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random

#Initializations
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a town hall different for balablu'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///MyBank.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://MyBank.db'
engine = create_engine('sqlite:///MyBank.db', echo=True)
app.config.from_object(__name__)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
#bcrypt = Bcrypt(app)
s = serializer(app.config['SECRET_KEY'])
mail = Mail(app)



#Forms
class RegisterForm(FlaskForm):
    name = StringField('Name',validators=[DataRequired(), Length(min=1,max=100)])
    email = StringField('Email Address', validators=[DataRequired(), Length(min=7, max=100)])
    phone = StringField('Phonenumber', validators=[DataRequired(), Length(min=3, max=20)])
    #acctNumber = StringField('Account Number',validators=[DataRequired(),Length(min=10,max=21)])
    acctBalance = StringField("Amount deposited",validators=[DataRequired(),Length(min=4,max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(),EqualTo('password')])
    pin = PasswordField('Create your banking pin',validators=[DataRequired(),Length(min=4,max=4)])
    confirmPin = PasswordField('Confirm your pin', validators=[DataRequired(),EqualTo('pin')])
    submit = SubmitField('Register')

    '''def validate_email(self, email):
        email = session.query(Customer).filter_by(email=email.data).first()
        if email:
            raise ValidationError('This email address already exists. Please choose a different one.')

    def validate_phone(self, phone):
        phone = session.query(Customer).filter_by(phone=phone.data).first()
        if phone:
            raise ValidationError('This phone number already exists. Please choose another one')

'''
class LoginForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Length(min=7, max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=20)])
    #remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class TransferForm(FlaskForm):
    receiver = StringField('Enter recipient\'s account number', validators=[DataRequired(), Length(min=8, max=12)])
    amount = StringField('Enter amount you want to transfer', validators=[DataRequired(), Length(min=3, max=5)])
    submit = SubmitField('Submit')

#Models
@login_manager.user_loader
def load_user(user_id):
    return session.query(Customer).get(int(user_id))

class Customer(Base,UserMixin):
    __tablename__ = 'customer'
    id = Column(Integer, primary_key=True)
    name = Column(String(100),nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    phone = Column(String(20), unique=True, nullable=False)
    acctNumber = Column(String(21), unique=True, nullable=False)
    acctBalance = Column(String(100), nullable=False)
    password = Column(String(20),nullable=False)
    pin = Column(String(4),nullable=False)
    date_registered = Column(DateTime, default=datetime.utcnow)
    confirmed = Column(Boolean, default=False)
    
    def __repr__(self):
        return f'''Customer('{self.name}','{self.email}','{self.phone}','{self.acctNumber}','{self.password}',
        '{self.confirmed}','{self.acctBalance}','{self.pin}')'''

    def get_reset_token(self, expires_sec=1800):
        s = serializer(app.config['SECRET_KEY'],expires_sec)
        return s.dumps({'user_id':self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = serializer(app.config['SECRET_KEY'])
        try:
            s.loads(token)['user_id']
        except:
            return None
        return session.query(Customer).get(user_id)

#Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html', title='AboutNamssn')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.validate_on_submit():
        '''numbers = '0123456789'
        tenNums = random.sample(numbers, 10)
        acct_number = ''.join(tenNums)'''
        hashed_password = generate_password_hash(form.password.data)
        numbers = form.phone.data
        list_num = list(numbers)
        list_num.remove(list_num[0])
        acct_number = ''.join(list_num)
        Base.metadata.create_all(engine)
        customer = Customer(name=form.name.data, email=form.email.data, 
        phone=form.phone.data, acctNumber=acct_number,password=hashed_password, acctBalance=form.acctBalance.data, pin=form.pin.data)
        session.add(customer)
        session.commit()
        flash('Form was submitted successfully','success')
    if request.method == 'GET':
        return render_template('register.html', title='Register', form=form)
    email = request.form['email']
    token = s.dumps(email, salt='confirm-email')
    link = url_for('confirm_email', token=token, _external=True)
    msg_body = f' Your account number is {acct_number} \n Please click {link} to verify your account'

    email_sender = os.environ['EMAIL']
    email_receiver = [email]
    email_password = os.environ['EMAIL_PASSWORD']
    email_subject = 'Confirm Email'
    email_body = msg_body

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = email_subject
    em.set_content(email_body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp@gmail.com',465,context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())
    return f'''<h4>We sent a link to {form.email.data}. Please click the link to confirm
    that you are the real owner of the email address provided.'''


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm')
    except(itsdangerous.SignatureExpired, itsdangerous.BadTimeSignature) as error:
        if str(error).endswith('seconds'):
            error_message = 'This token has expired. Please try again'
        elif str(error).endwith('does not match'):
            error_message = 'This token is invalid. Please check and try again'
        return error_message
    else:
        owner_email = request.form.get('email')
        owner = session.query(Customer).filter_by(email=owner_email).first()
        owner.confirmed = True
        session.commit()
    return '''<h1>Registration was successful</h1>'''
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        email = session.query(Customer).filter_by(email=form.email.data).first()
        #password = email.password
        if email and check_password_hash(email.password,form.password.data):
            login_user(email)
            next_page = request.args.get('next')
            flash(f'Login successful.', 'success')
            return redirect(next_page) if next_page else redirect(url_for('account'))
        else:
            flash(f'Login unsuccessful. Please check email or password', 'danger')  
    return render_template('login.html', title='LoginHere', form=form)

@app.route('/account')
@login_required
def account():
    emailAddress = current_user.email
    return render_template('account.html',emailAddress=emailAddress)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/checkBalance')
@login_required
def checkBalance():
    return render_template('checkBalance.html')

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    form = TransferForm()
    if form.validate_on_submit():
        receiver = session.query(Customer).filter_by(acctNumber = form.receiver.data).first()
        if int(current_user.acctBalance) <= int(form.amount.data):
            return '<h1>Insufficient Funds</h1>'
        if receiver:
            current_user.acctBalance = int(current_user.acctBalance) - int(form.amount.data)
            receiver.acctBalance = str(int(receiver.acctBalance) + int(form.amount.data))
            session.commit()
        else:
            return '<h1>Invalid acct number provided</h1>'

        sendDebitMail()
        sendCreditMail()
        return f'''
            <div class="container"><h1>
            You have successfully transferred {form.amount.data} to {receiver.name}</h1>
            </div>
            '''
    return render_template('transfer.html', form=form)

def sendDebitMail():
    form = TransferForm()
    transDate = datetime.now()
    email_sender = os.environ['EMAIL']
    email_receiver = current_user.email
    email_password = os.environ['EMAIL_PASSWORD']
    email_subject = 'My Bank'
    receiver = session.query(Customer).filter_by(acctNumber=form.receiver.data).first()
    email_body = f'''
    Txn: Debit
    Acc: {current_user.acctNumber}
    Description: Transfer to {receiver.name}, {receiver.acctNumber}
    Date: {transDate}
    Balance: {current_user.acctBalance}
    '''

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = email_subject
    em.set_content(email_body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp@gmail.com',465,context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())

def sendCreditMail():
    transDate = datetime.now()
    email_sender = os.environ['EMAIL']
    email_receiver = receiver
    email_password = os.environ['EMAIL_PASSWORD']
    email_subject = 'My Bank'
    email_body = f'''
    Txn: Credit
    Acc: {receiver.acctNumber}
    Description: Received from {sender.name}
    Date: {transDate}
    Balance: {receiver.acctBalance}
    '''

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = email_subject
    em.set_content(email_body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp@gmail.com',465,context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())

@app.errorhandler(404)
def not_found(e):
    return render_template('error404.html'), 404
    
if __name__ == '__main__':
    app.run(debug=True)