from flask import Flask, request, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class Users(db.Model):
    Email = db.Column(db.String(80), primary_key=True)
    Nickname = db.Column(db.String(50))
    Password = db.Column(db.String(80), nullable=False)
    FName = db.Column(db.String(50), nullable=False)
    LName = db.Column(db.String(50), nullable=False)

    def __init__(self, Email, Nickname, Password, Fname, LName):
        self.Email = Email
        self.Nickname = Nickname
        self.Password = Password
        self.FName = Fname
        self.LName = LName


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(Email=data['Email']).first()
        except:
            db.session.close()
            return jsonify({'message' : 'Token is invalid!'}), 401
        db.session.close()
        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    return current_user.Email

@app.route('/register', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        if 'Nickname' not in data:
            data['Nickname']= None
        doble_user = Users.query.filter_by(Email=data['Email']).first()
        if doble_user:
            db.session.close()
            return jsonify({'message': 'there is already a user with that Email'}), 400
        hashed_password = generate_password_hash(data['Password'], method='sha256')
        new_user = Users(Email=data['Email'], Nickname=data['Nickname'], Password=hashed_password, LName=data['Lname'],
                         Fname=data['Fname'])
        db.session.add(new_user)
        db.session.commit()
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message' : 'New user created!'})

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if 'Email' not in data or 'Password' not in data:
            return make_response('you didnt give me Email or Password', 400)
        user = Users.query.filter_by(Email=data['Email']).first()
        if not user:
            db.session.close()
            return make_response('user or password is not correct', 400)
        if check_password_hash(user.Password, data['Password']):
            token = jwt.encode({'Email' : user.Email, 'exp' : (datetime.datetime.utcnow() + datetime.timedelta(minutes=30 ))}, app.config['SECRET_KEY'], algorithm='HS256')
            db.session.close()
            return jsonify({'token' : token.decode('UTF-8')})
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400

@app.route("/")
@app.route("/home")
def home():
    return "<h1>Home Page</h1>"


@app.route("/about")
def about():
    return "<h1>About Page</h1>"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)