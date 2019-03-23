from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user #login_required
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY']= '0Oxcxff7F8905FCcbiI388847XFx7cfg6'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/User/Documents/program/python/site3/database.db' 
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'form'




class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(80), unique=True)
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20))
    content = db.Column(db.String(200))
    

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=2, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=2, max=80)])
    remember = BooleanField('remember me')
class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=2, max=15)] )
    email = StringField('email', validators=[InputRequired(), Length(min=4, max=80)])
    password = PasswordField('şifre', validators=[InputRequired(), Length(min=8, max=80)])



@app.route('/')
def index():
    return render_template('index.html')
@app.route('/drugs')
def drugs():
    return render_template('drugs.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('form'))


@app.route('/form', methods=['GET', 'POST'])
def form():
    form = LoginForm()
    posts = Post.query.all()
    

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return render_template('form.html', form=form)

        return render_template('form.1.html', form= form, posts = posts)
        #return '<script>alert("Kullanıcı adı veya şifre yanlış girildi");</script>'

    return render_template('form.html', form=form, posts = posts)

"""
@app.route('/add', methods=['POST'])
@login_required
def add():
    post = Post(title=request.form['başlık'], content=request.form['konu'])
    db.session.add(post)
    db.session.commit()

    return redirect(url_for('form'))
"""

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/topluluk', methods= ['GET', 'POST'])
@login_required
def topluluk():
    posts = Post.query.all()
    


    return render_template('topluluk.html', posts= posts)
    #return redirect(url_for('topluluk', post=posts))

@app.route('/add', methods=['POST'])
@login_required
def add():
    post = Post(title=request.form['başlık'], content=request.form['konu'])
    db.session.add(post)
    db.session.commit()

    return redirect(url_for('olusdur.html'))


@app.route('/yeni konu', methods=['POST'])
@login_required
def konu():
    render_template('olusdur.html')



if __name__ == '__main__':
    app.run(debug=True)
