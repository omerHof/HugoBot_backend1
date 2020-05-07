from flask import Flask, request, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from collections import defaultdict
from functools import wraps
from flask_cors import CORS
# from KarmaLego_Framework import RunKarmaLego
# import data1
import uuid
import time
import json
import os
import csv
from werkzeug.utils import secure_filename
import zipfile

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)


# this users table
class Users(db.Model):
    Email = db.Column(db.String(80), primary_key=True)
    institute = db.Column(db.String(50), nullable=False)
    degree = db.Column(db.String(10), nullable=False)
    Password = db.Column(db.String(80), nullable=False)
    FName = db.Column(db.String(50), nullable=False)
    LName = db.Column(db.String(50), nullable=False)
    my_datasets = db.relationship('info_about_datasets', backref='owner', lazy='subquery')
    Permissions = db.relationship('Permissions', backref='owner', lazy='subquery')
    ask_permissions = db.relationship('ask_permissions', backref='owner', lazy='subquery')


# this is the info about the metadata
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
    discretization = db.relationship('discretization', backref='dataset', lazy='subquery')


# table than handles the permissions
class Permissions(db.Model):
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50), db.ForeignKey('info_about_datasets.Name'), primary_key=True)


# table that handles the permitions that a user wants
class ask_permissions(db.Model):
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50), db.ForeignKey('info_about_datasets.Name'), primary_key=True)


class discretization(db.Model):
    id = db.Column(db.String(150), primary_key=True)
    PAA = db.Column(db.Integer, nullable=False)
    AbMethod = db.Column(db.String(25), nullable=False)
    NumStates = db.Column(db.Integer, nullable=False)
    InterpolationGap = db.Column(db.Integer, nullable=False)
    KnowledgeBasedFile_name = db.Column(db.String(120))
    GradientFile_name = db.Column(db.String(120))
    binning_by_value = db.Column(db.Boolean, nullable=False)
    karma_lego = db.relationship('karma_lego', backref='discretization', lazy='subquery')
    dataset_Name = db.Column(db.String(150), db.ForeignKey('info_about_datasets.Name'), nullable=False)


class karma_lego(db.Model):
    id = db.Column(db.String(150), primary_key=True)
    epsilon = db.Column(db.Float)
    min_ver_support = db.Column(db.Float, nullable=False)
    num_relations = db.Column(db.Integer, nullable=False)
    max_gap = db.Column(db.Integer, nullable=False)
    max_tirp_length = db.Column(db.Integer, nullable=False)
    index_same = db.Column(db.Boolean, nullable=False)
    discretization_name = db.Column(db.String(150), db.ForeignKey('discretization.id'), nullable=False)


# this function checks if the user is connected by checking the token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        print(token)

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(Email=data['Email']).first()
        except:
            db.session.close()
            print("token invalid. client rejected.")
            return jsonify({'message': 'Token is invalid!'}), 401
        db.session.close()
        return f(current_user, *args, **kwargs)

    return decorated


# this function asks for permission, it takes one argument in the url
# which is the name of the dataset like "dataset=datasetName"
@app.route('/askPermition', methods=['GET'])
@token_required
def ask_permition(current_user):
    try:
        dataset_name = request.args.get('dataset')
        dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
        ask = ask_permissions(owner=current_user, dataset=dataset)
        db.session.add(ask)
        db.session.commit()
        db.session.close()
        return jsonify({'message': 'permission asked!'})
    except:
        return jsonify({'message': 'problem with data'}), 400


# brings all the data you need to load the mail
@app.route('/loadMail', methods=['GET'])
@token_required
def loadMail(current_user):
    try:
        my_datasets = current_user.my_datasets
        to_return = {}
        to_return["myDatasets"] = {}
        x = 0
        for curr_dataset in my_datasets:
            full_name = current_user.FName + " " + current_user.LName
            to_return["myDatasets"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),
                                               "Owner": full_name,
                                               "Category": curr_dataset.category,
                                               "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        users_permissions = Permissions.query.filter_by(Email=current_user.Email).all()
        to_return["myPermissions"] = {}
        x = 0
        for curr_record in users_permissions:
            curr_dataset = curr_record.dataset
            full_name = current_user.FName + " " + current_user.LName
            to_return["myPermissions"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),
                                                  "Owner": full_name,
                                                  "Category": curr_dataset.category,
                                                  "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        users_ask_permissions = ask_permissions.query.filter_by(Email=current_user.Email).all()
        to_return["askPermissions"] = {}
        x = 0
        for curr_record in users_ask_permissions:
            curr_dataset = curr_record.dataset
            full_name = current_user.FName + " " + current_user.LName
            to_return["askPermissions"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),
                                                   "Owner": full_name,
                                                   "Category": curr_dataset.category,
                                                   "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an eror!'}), 500


# takes 2 arguments in the url, 'dataset' and 'userEmail' and gives a user a permission
@app.route('/acceptPermission', methods=['GET'])
@token_required
def accept_permission(current_user):
    try:
        dataset_name = request.args.get('dataset')
        user_email = request.args.get('userEmail')
        record = ask_permissions.query.filter_by(Email=user_email, name_of_dataset=dataset_name).first()
        user_email_check = record.dataset.owner.Email
        if (current_user.Email != user_email_check):
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


# sends all the info about the data sets
@app.route('/getAllDataSets', methods=['GET'])
def get_all_datasets():
    # x=0
    # while(x<4317777):
    #   print(x)
    #  x=x+1
    # user = Users.query.filter_by(Email="2").first()
    # dataset1 = info_about_datasets(Name='data1', Description='ehtyhtyr', Rel_Path='hjswcwelk', public_private='public', category='sports', size=8.54, views=0, downloads=0, owner=user)
    # dataset2 = info_about_datasets(Name='data2', Description='ehtyhtyr', Rel_Path='hjswcwelk', public_private='public', category='sports', size=8.54, views=0, downloads=0, owner=user)
    # dataset3 = info_about_datasets(Name='data3', Description='ehtyhtyr', Rel_Path='hjswcwelk',public_private='public',category='sports', size=8.54, views=0, downloads=0, owner=user)
    # db.session.add(dataset1)
    # db.session.add(dataset2)
    # db.session.add(dataset3)
    # db.session.commit()
    # dataset1= info_about_datasets.query.filter_by(Name="data1").first()
    # disc= discretization(id='1234', dataset=dataset1)
    # db.session.add(disc)
    # db.session.commit()
    # dataset2 = info_about_datasets.query.filter_by(Name="data2").first()
    # print(dataset1)
    # print(dataset2)
    # data1 = Permissions(owner=user, dataset=dataset1)
    # data2 = Permissions(owner=user, dataset=dataset2)
    # db.session.add(data1)
    # db.session.add(data2)
    # db.session.commit()

    try:
        datasets = info_about_datasets.query.all()
        to_return = {}
        x = 0
        to_return["lengthNum"] = len(datasets)
        for curr_dataset in datasets:
            full_name = curr_dataset.owner.FName + " " + curr_dataset.owner.LName
            to_return[str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size), "Owner": full_name,
                                 "Category": curr_dataset.category, "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an eror!'}), 500


def check_exists(disc, epsilon, max_gap, verticale_support, num_relations, index_same, max_tirp_length):
    exists = karma_lego.query.filter_by(epsilon=epsilon, min_ver_support=verticale_support, num_relations=num_relations,
                                        max_gap=max_gap, max_tirp_length=max_tirp_length, index_same=index_same,
                                        discretization=disc).first()
    if (exists == None):
        return False
    return True


def check_if_already_exists(dataset, PAA, AbMethod, NumStates, InterpolationGap, GradientFile_name,
                            KnowledgeBasedFile_name):
    exists = discretization.query.filter_by(dataset=dataset, PAA=PAA, AbMethod=AbMethod, NumStates=NumStates,
                                            InterpolationGap=InterpolationGap,
                                            GradientFile_name=GradientFile_name,
                                            KnowledgeBasedFile_name=KnowledgeBasedFile_name).first()
    if (exists == None):
        return False
    return True


def get_dataset_name(disc):
    dataset = disc.dataset
    dataset_name = dataset.Name
    return dataset_name


def create_directory_disc(dataset_name, discretization_id):
    path = dataset_name + "/" + discretization_id
    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)
    return path


def unzip(from_path, to_path, file_name):
    with zipfile.ZipFile(from_path + '/' + file_name, 'r') as zip_ref:
        zip_ref.extractall(to_path)


def delete_not_necesery(directory_path):
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            continue
        else:
            os.remove(filename)


@app.route('/getDataOnDataset', methods=['GET'])
def get_data_on_dataSet():
    # try:
    dataset_name = request.args.get("id")
    print(dataset_name)
    discretizations = discretization.query.filter_by(dataset_Name=dataset_name).all()
    disc_to_return = {}
    x = 0
    num = 0
    disc_to_return["lengthNum"] = len(discretizations)
    karma_arr = []
    for curr_disc in discretizations:
        karma_arr.append(karma_lego.query.filter_by(discretization=curr_disc).all())
        num = num + len(karma_arr[x])
        if curr_disc.binning_by_value == True:
            bin = "true"
        else:
            bin = "false"
        disc_to_return[str(x)] = {"MethodOfDiscretization": str(curr_disc.AbMethod),
                                  "BinsNumber": str(curr_disc.NumStates),
                                  "InterpolationGap": str(curr_disc.InterpolationGap),
                                  "PAAWindowSize": str(curr_disc.PAA), "BinningByValue": bin, "id": str(curr_disc.id)}
        x = x + 1
    x = 0
    karma_to_return = {}
    karma_to_return["lengthNum"] = num

    for karma in karma_arr:
        for curr_karma in karma:
            if curr_karma.index_same == True:
                i_s = "true"
            else:
                i_s = "false"
            print(str(curr_karma.epsilon))
            karma_to_return[str(x)] = {"MethodOfDiscretization": str(curr_karma.discretization.AbMethod),
                                       "BinsNumber": str(curr_karma.discretization.NumStates),
                                       "InterpolationGap": str(curr_karma.discretization.InterpolationGap),
                                       "PAAWindowSize": str(curr_karma.discretization.PAA),
                                       "karma_id": str(curr_karma.id),
                                       "epsilon": str(curr_karma.epsilon),
                                       "VerticalSupport": str(curr_karma.min_ver_support),
                                       "MaxGap": str(curr_karma.max_gap),
                                       "numRelations": str(curr_karma.num_relations),
                                       "maxTirpLength": str(curr_karma.max_tirp_length),
                                       "indexSame": i_s,
                                       "discId": curr_karma.discretization.id}
            x = x + 1
    print(karma_to_return)
    to_return = {"disc": disc_to_return, "karma": karma_to_return}
    db.session.close()
    return jsonify(to_return)
    # except:
    db.session.close()
    return jsonify({'message': 'there has been an eror!'}), 500


@app.route('/addNewDisc', methods=['POST'])
def add_new_disc():
    data = request.form
    print("hello")
    PAA = int(data['PAA'])
    AbMethod = str(data['AbMethod'])
    NumStates = int(data['NumStates'])
    InterpolationGap = int(data['InterpolationGap'])
    dataset_name = str(data["datasetName"])
    binning = data["BinningByValue"]
    if (binning == 'true'):
        binning = True
    else:
        binning = False
    print("hello")
    if 'GradientFile' not in data:
        GradientFile = request.files["GradientFile"]
        GradientFile.save(
            # os.path.join('C:/Users/yonatan/PycharmProjects/HugoBotServer', secure_filename(GradientFile.filename)))
            os.path.join('C:/Users/Raz/PycharmProjects/HugoBotServer', secure_filename(GradientFile.filename)))
        GradientFile_name = GradientFile.filename
    else:
        GradientFile_name = None
    if 'KnowledgeBasedFile' not in data:
        KnowledgeBasedFile = request.files["KnowledgeBasedFile"]
        # KnowledgeBasedFile.save(os.path.join('C:/Users/yonatan/PycharmProjects/HugoBotServer',
        #                                      secure_filename(KnowledgeBasedFile.filename)))
        KnowledgeBasedFile.save(os.path.join('C:/Users/Raz/PycharmProjects/HugoBotServer',
                                             secure_filename(KnowledgeBasedFile.filename)))
        KnowledgeBasedFile_name = KnowledgeBasedFile.filename
    else:
        KnowledgeBasedFile_name = None
    dataset1 = info_about_datasets.query.filter_by(Name=dataset_name).first()
    if check_if_already_exists(dataset1, PAA, AbMethod, NumStates, InterpolationGap, GradientFile_name,
                               KnowledgeBasedFile_name):
        return jsonify({'message': 'already exists!'}), 400
    disc_id = str(uuid.uuid4())
    print("hello")
    disc = discretization(binning_by_value=binning, id=disc_id, dataset=dataset1, PAA=PAA, AbMethod=AbMethod,
                          NumStates=NumStates,
                          InterpolationGap=InterpolationGap, GradientFile_name=GradientFile_name,
                          KnowledgeBasedFile_name=KnowledgeBasedFile_name)
    db.session.add(disc)
    db.session.commit()
    create_directory_disc(dataset_name, disc_id)
    # with zipfile.ZipFile('somePath/bla2.zip', 'r') as zip_ref:
    #    zip_ref.extractall('C:/Users/yonatan/PycharmProjects/HugoBotServer')
    return "hello"


def create_directory_for_dataset(dataset_name):
    try:
        os.mkdir(dataset_name)
    except OSError:
        print("Creation of the directory %s failed" % dataset_name)
    else:
        print("Successfully created the directory %s " % dataset_name)
    return dataset_name


def create_directory(dataset_name, discretization_id, KL_id):
    path = dataset_name + "/" + discretization_id + "/" + KL_id
    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)
    return path


def check_for_bad_user(KL, user_id):
    if (KL.discretization.dataset.owner.Email == user_id):
        return False
    else:
        return True


def check_for_bad_user_disc(disc, user_id):
    if (disc.dataset.owner.Email == user_id):
        return False
    else:
        return True


@app.route('/getTIM', methods=['POST'])
@token_required
def get_TIM(current_user):
    data = request.get_json()
    kl_id = data["kl_id"]
    class_num = data["class_num"]
    KL = karma_lego.query.filter_by(id=kl_id).first()
    if (check_for_bad_user(KL, current_user.Email)):
        return jsonify({'message': 'dont try to fool me, you dont own it!'}), 400
    disc = KL.discretization.id
    dataset = KL.discretization.dataset.Name
    return send_file(dataset + '/' + disc + '/' + kl_id + '/' + class_num)


@app.route('/getTIM1', methods=['GET', 'POST'])
def get_TIM1():
    return send_file("C:/Users/yonatan/PycharmProjects/hello.zip")


@app.route('/getDISC', methods=['POST'])
# @token_required
def get_DISC():
    data = request.form
    disc_id = data["disc_id"]
    disc = discretization.query.filter_by(id=disc_id).first()
    # if (check_for_bad_user_disc(disc, current_user.Email)):
    #     return jsonify({'message': 'dont try to fool me, you dont own it!'}), 400
    dataset = disc.dataset.Name
    return send_file(dataset + '/' + disc_id + '/states.csv')


@app.route('/addTIM', methods=['POST'])
def add_TIM():
    x = 0
    while (x < 4317777):
        print(x)
        x = x + 1
    data = request.form
    discretization_id = str(data['DiscretizationId'])
    if 'Epsilon' not in data:
        epsilon = float(0.0000)
    else:
        epsilon = float(data['Epsilon'])
    max_gap = int(data['Max Gap'])
    verticale_support = float(data['min_ver_support'])
    num_relations = int(data['num_relations'])
    max_tirp_length = int(data['max Tirp Length'])
    index_same = str(data['index_same'])
    if (index_same == 'true'):
        index_same = True
    else:
        index_same = False
    disc = discretization.query.filter_by(id=discretization_id).first()
    if (check_exists(disc, epsilon, max_gap, verticale_support, num_relations, index_same, max_tirp_length)):
        return jsonify({'message': 'already exists!'}), 400
    dataset_name = get_dataset_name(disc)
    KL_id = str(uuid.uuid4())
    KL = karma_lego(id=KL_id, epsilon=epsilon, min_ver_support=verticale_support, num_relations=num_relations,
                    max_gap=max_gap, max_tirp_length=max_tirp_length, index_same=index_same, discretization=disc)
    db.session.add(KL)
    db.session.commit()
    """
    create_directory(dataset_name, discretization_id, KL_id)
    directory_path = dataset_name + "/" + discretization_id
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            start_time = time.time()
            print(time.time() - start_time)
            support_vec = verticale_support
            num_relations = num_relations
            max_gap = max_gap
            epsilon= epsilon
            max_tirp_length= max_tirp_length
            path = 'C:/Users/yonatan/PycharmProjects/HugoBotServer/' + directory_path + '/' + filename
            print(filename)
            out_path = 'C:/Users/yonatan/PycharmProjects/HugoBotServer/' + directory_path + '/' + KL_id + '/' + filename
            print_output_incrementally = True
            entity_ids_num = 2
            index_same = index_same
            semicolon_end = True
            need_one_sized = True
            lego_0, karma_0 = RunKarmaLego.runKarmaLego(time_intervals_path=path, output_path=out_path, index_same=index_same,epsilon=epsilon,
                                           incremental_output=print_output_incrementally, min_ver_support=support_vec,
                                           num_relations=num_relations, skip_followers=False, max_gap=max_gap, label=0,
                                           max_tirp_length=max_tirp_length, num_comma=2, entity_ids_num=entity_ids_num,
                                           semicolon_end=semicolon_end, need_one_sized=need_one_sized)
            print("hello")
            if not print_output_incrementally:
                lego_0.print_frequent_tirps(out_path)
            total_time = time.time() - start_time
            print(total_time)
        else:
            continue
    """
    return "hello"


# post reqeust that gets a json with 'Email',
# 'Nickname'(optional), 'Password', 'Lname', 'Fname'
@app.route('/register', methods=['POST'])
def create_user():
    try:
        data = request.form
        doble_user = Users.query.filter_by(Email=data['Email']).first()
        if doble_user:
            db.session.close()
            print("hello")
            return jsonify({'message': 'there is already a user with that Email'}), 400
        hashed_password = generate_password_hash(data['Password'], method='sha256')
        new_user = Users(Email=data['Email'], institute=data["Institute"], degree=data["Degree"],
                         Password=hashed_password, LName=data['Lname'],
                         FName=data['Fname'])
        db.session.add(new_user)
        db.session.commit()
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'New user created!'})


# gets 'Email' and 'Password' and gives back a token than you should.
# send with key value like x-access-token in the header
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.form
        if 'Email' not in data or 'Password' not in data:
            return make_response('you didnt give me Email or Password', 400)
        user = Users.query.filter_by(Email=data['Email']).first()
        if not user:
            db.session.close()
            return make_response({'message': 'user or password is not correct'}, 400)
        if check_password_hash(user.Password, data['Password']):
            token = jwt.encode(
                {'Email': user.Email, 'exp': (datetime.datetime.utcnow() + datetime.timedelta(minutes=3000))},
                app.config['SECRET_KEY'], algorithm='HS256')
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


output_dir = " C:/Downloads/HugoBot"  # info generated by server before calling the function
output_dir_name = "HugoBot"  # same as output_dir


# temporal-abstraction 'Path to dataset file' 'Path to output dir' per-property
# -s (when using Gradient or KnowledgeBased) 'Path to states file' (when using Gradient or KnowledgeBased)
# 'Path to Preprocessing file' 'Path to Temporal Abstraction file'
def empty_string():
    return ""


config_3 = defaultdict(empty_string)
config_3["cli_path"] = " C:/Downloads/beta-release-v1.1.5_03-01-2020/cli.py"
config_3["mode"] = " temporal-abstraction"
config_3["dataset_path"] = " C:/Downloads/EdoFiles/FAGender.csv"
config_3["output_dir"] = " C:/Downloads/HugoBot"
config_3["output_dir_name"] = "HugoBot"
config_3["dataset_or_property"] = " per-property"
config_3["preprocessing_path"] = " C:/Downloads/EdoFiles/preprocessing.csv"
config_3["temporal_abstraction_path"] = " C:/Downloads/EdoFiles/temporal_abstraction.csv"


def run_hugobot(config):
    command = ""
    command += "python"
    command += config["cli_path"]
    command += config["mode"]
    command += config["dataset_path"]
    command += config["output_dir"]
    command += config["dataset_or_property"]
    command += config["max_gap"]
    command += config["discretization"]
    command += config["abstraction_method"]
    command += config["number_of_bins"]
    command += config["preprocessing_path"]
    command += config["temporal_abstraction_path"]

    os.system("if not exist" + output_dir + " mkdir " + output_dir_name)
    os.system(command)


@app.route("/stepone", methods=["POST"])
def upload_stepone():
    try:
        # Extract user input from the form:
        dataset_name = request.form['datasetName']
        category = request.form['category']
        public_private = request.form['publicPrivate']
        raw_data_file = request.files['file']
        description = request.form['description']
        dataset_source = request.form['datasetSource']

        # Echo it in the server (sanity check)
        print(dataset_name)
        print(category)
        print(public_private)
        print(raw_data_file)
        print(description)
        print(dataset_source)

        # Dataset File: user input

        # Validate dataset file integrity

        # Save the dataset file
        create_directory_for_dataset(dataset_name)
        raw_data_file.save(os.path.join('C:/Users/Raz/PycharmProjects/HugoBotServer',
                                        dataset_name,
                                        secure_filename(raw_data_file.filename)))

        # Now, save the info as a tuple in the DB and the file as part of the file system:
        # info_about_datasets tuple:
        # Name (PK), Pub_date, Description, Rel_path, Public/private, Category, Size, Views, Downloads, Email
        # Name: user input
        # Pub_date: generated (get current time)
        # Description: user input
        # Rel_path: generated (using user input - the name of the directory is the dataset name)
        # Public/private: user input
        # Category: user input
        # Size: generated (calculated from file)
        size = os.path.getsize(os.path.join('C:/Users/Raz/PycharmProjects/HugoBotServer',
                                            dataset_name,
                                            raw_data_file.filename))
        # Views: generated (instantiated to 0)
        views = 0
        # Downloads: generated (instantiated to 0)
        downloads = 0
        # Email: user input (identifier of the user)
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'Dataset Successfully Validated!'})


@app.route("/steptwo", methods=["POST"])
def upload_steptwo():
    try:
        # file = request.files['file']
        file = request.form['file']
        print(file)
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'VMap Registered Successfully!'})


@app.route("/steptwocreate", methods=['POST'])
def step_two_create():
    try:
        file = request.form['csv']
        print(file)
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'VMap Registered Successfully!'})


@app.route("/stepthree", methods=["POST"])
def upload_stepthree():
    try:
        # file = request.files['file']
        file = request.form['file']
        print(file)
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'Entity File Successfully Uploaded!'})


@app.route("/getInfo", methods=["GET"])
def get_all_info_on_dataset():
    dataset_name = request.args.get("id")
    print(dataset_name)
    return jsonify({"Name": "data1",
                    "category": "medical",
                    "owner_name": "raz shtrauchler",
                    "source": "raz himself",
                    "Description": "a fitting description",
                    "size": "2.432 MB",
                    "views": "34",
                    "downloads": "3"}), 200


@app.route("/getVMapFile", methods=["GET"])
def get_vmap_file():
    dataset_name = request.args.get("id")
    print(dataset_name)
    return send_file(dataset_name + '/' + 'VMap.csv'), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)
