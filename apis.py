from flask import Flask, request, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_cors import CORS
import json


app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

#this users table
class Users(db.Model):
    Email = db.Column(db.String(80), primary_key=True)
    Nickname = db.Column(db.String(50))
    Password = db.Column(db.String(80), nullable=False)
    FName = db.Column(db.String(50), nullable=False)
    LName = db.Column(db.String(50), nullable=False)
    my_datasets = db.relationship('info_about_datasets', backref='owner', lazy='subquery')
    Permissions = db.relationship('Permissions', backref='owner', lazy='subquery')
    ask_permissions = db.relationship('ask_permissions', backref='owner', lazy='subquery')


#this is the info about the metadata
class info_about_datasets(db.Model):
    Name = db.Column(db.String(50), primary_key=True)
    pub_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    Description = db.Column(db.String(255))
    Rel_Path = db.Column(db.String(128), nullable=False)
    public_private = db.Column(db.String(8), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    size = db.Column(db.Float, nullable=False)
    views = db.Column(db.Integer, nullable=False)
    downloads = db.Column(db.Integer, nullable=False)
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), nullable=False)
    Permissions = db.relationship('Permissions', backref='dataset', lazy='subquery')
    ask_permissions = db.relationship('ask_permissions', backref='dataset', lazy='subquery')

#table than handles the permissions
class Permissions(db.Model):
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50),db.ForeignKey('info_about_datasets.Name'), primary_key=True)

#table that handles the permitions that a user wants
class ask_permissions(db.Model):
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50),db.ForeignKey('info_about_datasets.Name'), primary_key=True)



#this function checks if the user is connected by checking the token
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
#this function asks for permission, it takes one argument in the url
#which is the name of the dataset like "dataset=datasetName"
@app.route('/askPermition', methods=['GET'])
@token_required
def ask_permition(current_user):
    try:
        dataset_name= request.args.get('dataset')
        dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
        ask = ask_permissions(owner=current_user, dataset=dataset)
        db.session.add(ask)
        db.session.commit()
        db.session.close()
        return jsonify({'message' : 'permission asked!'})
    except:
        return jsonify({'message': 'problem with data'}), 400
    
#brings all the data you need to load the mail
@app.route('/loadMail', methods=['GET'])
@token_required
def loadMail(current_user):
    try:
        my_datasets= current_user.my_datasets
        to_return={}
        to_return["myDatasets"]={}
        x=0
        for curr_dataset in my_datasets:
            full_name = current_user.FName + " " + current_user.LName
            to_return["myDatasets"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size), "Owner": full_name,
                                               "Category": curr_dataset.category, "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        users_permissions = Permissions.query.filter_by(Email=current_user.Email).all()
        to_return["myPermissions"] = {}
        x = 0
        for curr_record in users_permissions:
            curr_dataset= curr_record.dataset
            full_name = current_user.FName + " " + current_user.LName
            to_return["myPermissions"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),"Owner": full_name,
                                                  "Category": curr_dataset.category,"PublicPrivate": curr_dataset.public_private}
            x = x + 1
        users_ask_permissions = ask_permissions.query.filter_by(Email=current_user.Email).all()
        to_return["askPermissions"] = {}
        x = 0
        for curr_record in users_ask_permissions:
            curr_dataset = curr_record.dataset
            full_name = current_user.FName + " " + current_user.LName
            to_return["askPermissions"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),"Owner": full_name,
                                                   "Category": curr_dataset.category,"PublicPrivate": curr_dataset.public_private}
            x = x + 1
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an eror!'}), 500

#takes 2 arguments in the url, 'dataset' and 'userEmail' and gives a user a permission
@app.route('/acceptPermission', methods=['GET'])
@token_required
def accept_permission(current_user):
    try:
        dataset_name = request.args.get('dataset')
        user_email = request.args.get('userEmail')
        record = ask_permissions.query.filter_by(Email=user_email, name_of_dataset=dataset_name).first()
        user_email_check = record.dataset.owner.Email
        if (current_user.Email!=user_email_check):
            db.session.close()
            return jsonify({'message': 'dont try to fool me, you dont own this dataset!'}), 400
        to_add = Permissions(Email=user_email, name_of_dataset=dataset_name)
        db.session.add(to_add)
        db.session.delete(record)
        db.session.commit()
        db.session.close()
        return jsonify({'message': 'permission accepted!'})
    except:
        return jsonify({'message': 'there has been an eror!'}), 500

#sends all the info about the data sets
@app.route('/getAllDataSets', methods=['GET'])
def get_all_datasets():
    #x=0
    #while(x<4317777):
     #   print(x)
      #  x=x+1
    user = Users.query.filter_by(Email="2").first()
    #dataset1 = info_about_datasets(Name='data1', Description='ehtyhtyr', Rel_Path='hjswcwelk', public_private='public', category='sports', size=8.54, views=0, downloads=0, owner=user)
    #dataset2 = info_about_datasets(Name='data2', Description='ehtyhtyr', Rel_Path='hjswcwelk', public_private='public', category='sports', size=8.54, views=0, downloads=0, owner=user)
    #dataset3 = info_about_datasets(Name='data3', Description='ehtyhtyr', Rel_Path='hjswcwelk',public_private='public',category='sports', size=8.54, views=0, downloads=0, owner=user)
    #db.session.add(dataset1)
    #db.session.add(dataset2)
    #db.session.add(dataset3)
    #db.session.commit()
    dataset1= info_about_datasets.query.filter_by(Name="data1").first()
    dataset2 = info_about_datasets.query.filter_by(Name="data2").first()
    print(dataset1)
    print(dataset2)
    data1 = Permissions(owner=user, dataset=dataset1)
    data2 = Permissions(owner=user, dataset=dataset2)
    db.session.add(data1)
    db.session.add(data2)
    db.session.commit()

    try:
        datasets= info_about_datasets.query.all()
        to_return= {}
        x=0
        to_return["lengthNum"]= len(datasets)
        for curr_dataset in datasets:
            full_name= curr_dataset.owner.FName + " " + curr_dataset.owner.LName
            to_return[str(x)]= {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size) ,"Owner": full_name, "Category": curr_dataset.category, "PublicPrivate": curr_dataset.public_private}
            x=x+1
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an eror!'}), 500

#post reqeust that gets a json with 'Email',
#'Nickname'(optional), 'Password', 'Lname', 'Fname'
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
                         FName=data['Fname'])
        db.session.add(new_user)
        db.session.commit()
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message' : 'New user created!'})

#gets 'Email' and 'Password' and gives back a token than you should
#send with key value like x-access-token in the header
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
            token = jwt.encode({'Email': user.Email, 'exp': (datetime.datetime.utcnow() + datetime.timedelta(minutes=3000))},app.config['SECRET_KEY'], algorithm='HS256')
            db.session.close()
            return jsonify({'token': token.decode('UTF-8')})
        else:
            db.session.close()
            return jsonify({'message': 'problem with data'}), 400
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