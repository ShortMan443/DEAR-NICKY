import os  
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os.path
import tempfile
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
import os
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
import os.path
import tempfile
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
#from werkzeug.utils import secure_filename

#UPLOAD_FOLDER = '/uploads'
#ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg'])

app = Flask(__name__)
#app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
  
app.config['SECRET_KEY'] = 'thisismytosecretkeynotforyoutsee'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(tempfile.gettempdir(), 'data.db')
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcZdY8UAAAAAKhGECwpKa-Tl37HDZhNRH7odW3C'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcZdY8UAAAAAG6n4DLMPQM_sQQGC3ZCgHPh2icV'
app.config['TESTING'] = True

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
admin = Admin(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.secret_key = 'notforu'

@app.route('/')
@app.route('/join')
def join():
    return render_template('join.html')

class Blogpost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    recaptcha = RecaptchaField()

admin.add_view(ModelView(Blogpost, db.session))
admin.add_view(ModelView(User, db.session))

@app.route('/home')
@app.route('/home.html') 
@login_required
def home():
    posts = Blogpost.query.all()
    user = User.query.all()
    #3date_posted = post.date_posted.strftime('%B %d, %Y')
    return render_template('home.html', posts=posts, user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('home'))
                #1flash('Logged In!')

        return '<h1>Invalid username or password</h1> <form action="/home"><input class="btn btn-success" type="submit" value="Go Back" /></form>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return render_template('true.html')
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('join'))

@app.route('/template') 
@app.route('/template.html')
def template():
    return render_template('template.html')

@app.route('/profile') 
@app.route('/profile.html') 
def profile():
    return render_template('profile.html')

@app.route('/post')
@app.route('/post.html')
def post():
    return render_template('contact.html')

@app.route('/addpost', methods=['POST'])
@login_required
def addpost():
    #below when u POST to the action of /addpost  then the name is here      title = request.form[<name>]
    title = request.form['title1'] # <input type="text" class="form-control" placeholder="Title" name="title1" id="title" required data-validation-required-message="Please enter a title.">
    author = request.form['author']
    content = request.form['content']

    post = Blogpost(title=title, author=author, content=content, date_posted=datetime.now())  #DEF THE BOSTS

    db.session.add(post) #ADDS THE POSTS
    db.session.commit() #COMMITS THE POSTS

    return redirect(url_for('home'))

@app.route('/delete_post/<int:posts_id>/', methods=('GET', 'POST'))

def delete_post(posts_id):
    posts = Blogpost.query.filter_by(id=posts_id).first_or_404()
    db.session.delete(posts)
    db.session.commit()
    return redirect(url_for('home'))

@login_required
@app.route('/bots')
def index():
    return render_template('bots.html')

@app.route('/add_task', methods=('GET', 'POST'))
def new_task():

	Email = request.form.get('Email')
	FirstName = request.form.get('FirstName')
	LastName = request.form.get('LastName')
	PhoneNum = request.form.get('PhoneNumber')
	Address = request.form.get('Address')
	shipping_city = request.form.get('shipping_city')
	State = request.form.get('State')
	ZipCode = request.form.get('ZipCode')
	CCnum = request.form.get('CC#')
	CC_MM = request.form.get('CC_MM')
	CC_YY = request.form.get('CC_YY')
	CC_CVV = request.form.get('CC_CVV')    
	pidcode = request.form.get('PID')
   


	global session
	endpoint0 = ('http://www.jimmyjazz.com/cart-request/cart/add/%s/1' %pidcode)
	response0 = session.get(endpoint0)

	
	endpoint1 = 'https://www.jimmyjazz.com/cart/checkout'
	response1 = session.get(endpoint1)

	soup = bs(response1.text,"html.parser")
	inputs = soup.find_all("input",{"name":"form_build_id"})
	form_build_id = inputs[0]["value"]

	payload0 = {
		"billing_email":Email,
		"billing_email_confirm":Email,
		"billing_phone":PhoneNum,
		"email_opt_in":"1",
		"shipping_first_name":FirstName,
		"shipping_last_name":LastName,
		"shipping_country_html":"United States",
		"shipping_address1":Address,
		"shipping_address2":"",
		"shipping_city":shipping_city,
		"shipping_state":State,
		"shipping_zip":ZipCode,
		"shipping_method":"0",
		"signature_required":"1",
		"billing_same_as_shipping":"1",
		"billing_first_name":"",
		"billing_last_name":"",
		"billing_country":"US",
		"billing_address1":"",
		"billing_address2":"",
		"billing_city":"",
		"billing_state":"",
		"billing_zip":"",
		"payment_type":"credit_card",
		"cc_type":"Visa",
		"cc_number":CCnum,
		"cc_exp_month":CC_MM,
		"cc_exp_year":CC_YY,
		"cc_cvv":CC_CVV,
		"gc_num":"",
		"form_build_id":form_build_id,
		"form_id":"cart_checkout_form"
	}

	endpoint2 = 'https://www.jimmyjazz.com/cart/checkout'
	response2 = session.post(endpoint2, data=payload0)

	#print("Checking out:")

	soup1 = bs(response2.text,"html.parser")
	inputs1 = soup.find_all("input",{"name":"form_build_id"})
	form_build_id1 = inputs1[0]["value"]

	payload1 = {
		"form_build_id":form_build_id1,
		"form_id":"cart_confirm_form"
	}
		
	endpoint3 = 'https://www.jimmyjazz.com/cart/confirm'
	response3 = session.post(endpoint3, data=payload1)
	
	return 'Done Check Email :)'
  

@app.errorhandler(404)
def error404(error):
    return render_template('profile.html')
