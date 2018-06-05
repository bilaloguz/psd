from flask import Flask, url_for, render_template, request, redirect, session
from passlib.hash import bcrypt
from werkzeug import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import ConfigParser

db_file = "sqlite:///web_db.db"
general_settings_file = "settings.cfg"
watch_settings_file = "watches.cfg"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = db_file
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
	
	id = db.Column(db.Integer, primary_key=True)	
	username = db.Column(db.String(10), unique=True, nullable=False, primary_key=False)
	password = db.Column(db.String(10), unique=False, nullable=False, primary_key=False)

	def __init__(self, username, password):
		self.username = username
		self.set_password(password)

	def set_password(self, password):
	        self.password = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password, password)

	def __repr__(self):
		return "<Username: {}>".format(self.username)

@app.route("/", methods=["POST", "GET"])
def login():
	if not session.get('logged_in'):
		return render_template('login.html')
	else:
		username = request.form['username']
		password = request.form['password']
		try:
			data = User.query().filter_by(username=username, password=password).first()
			if data is not None:
				session['logged_in'] = True
				return redirect(url_for('index'))
			else:
				return 'Login is unsuccessful.'
		except:
			return 'Login is unsuccessful.'		

@app.route('/logout')
def logout():
	session['logged_in'] = False
	return redirect(url_for('login'))

@app.route('/register')
def register():
	username = "root"
	password = "987Uei"
	user = User(username, password)
	db.session.add(user)
	try:
		db.session.commit()
		return "Done."
	except Exception as e:
		return str(e)

@app.route('/save')
def save():

@app.route('/index')
def index():
	Config = ConfigParser.ConfigParser()			
	Config.read(general_settings_file)
	general_settings = {}
	for section in Config.sections():
		for option in Config.options(section):
			general_settings[option] = Config.get(section, option)

	Config.read(watch_settings_file)
	all_watches_settings = {}
	for section in Config.sections():
		watch_settings = {}	
		for option in Config.options(section):
			watch_settings[option] = Config.get(section, option)
		all_watches_settings[section] = watch_settings

	return render_template("index.html", general_settings=general_settings, all_watches_settings=all_watches_settings)	

if __name__ == "__main__":
    app.run(debug=True)

