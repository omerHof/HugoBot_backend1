from flask import Flask, request, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from collections import defaultdict
from functools import wraps
from flask_cors import CORS
from KarmaLego_Framework import RunKarmaLego
# import data1
import uuid
import notify_by_email
import check_email
import time
# import json
import os
# import csv
from werkzeug.utils import secure_filename
import zipfile

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)


def empty_string():
    return ""


SERVER_ROOT = "C:/Users/Raz/PycharmProjects/HugoBotServer"
HUGOBOT_EXECUTABLE_PATH = "HugoBot-beta-release-v1.1.5_03-01-2020/cli.py"
CLI_PATH = SERVER_ROOT + '/' + HUGOBOT_EXECUTABLE_PATH
MODE = "temporal-abstraction"
DATASET_OR_PROPERTY = "per-property"


# this is the users table
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
    public_private = db.Column(db.String(8), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    size = db.Column(db.Float, nullable=False)
    views = db.Column(db.Integer, nullable=False)
    downloads = db.Column(db.Integer, nullable=False)
    source = db.Column(db.String(100))
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), nullable=False)
    Permissions = db.relationship('Permissions', backref='dataset', lazy='subquery')
    ask_permissions = db.relationship('ask_permissions', backref='dataset', lazy='subquery')
    discretization = db.relationship('discretization', backref='dataset', lazy='subquery')


# table than handles the permissions
class Permissions(db.Model):
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50), db.ForeignKey('info_about_datasets.Name'), primary_key=True)


# table that handles the permissions that a user wants
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


def check_for_authorization(current_user, dataset_name):
    per = Permissions.query.filter_by(name_of_dataset=dataset_name).first()
    dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
    if (per is None or current_user.Email != per.owner.Email) and (dataset.owner.Email != current_user.Email):
        return True
    else:
        return False


@app.route('/getDataOnDataset', methods=['GET'])
@token_required
def get_data_on_dataset(current_user):
    try:
        dataset_name = request.args.get("id")
        print(current_user)
        if check_for_authorization(current_user, dataset_name):
            return jsonify({'message': 'dont try to fool me, you dont own it!'}), 403
        discretizations = discretization.query.filter_by(dataset_Name=dataset_name).all()
        disc_to_return = {}
        x = 0
        num = 0
        disc_to_return["lengthNum"] = len(discretizations)
        karma_arr = []
        for curr_disc in discretizations:
            karma_arr.append(karma_lego.query.filter_by(discretization=curr_disc).all())
            num = num + len(karma_arr[x])
            if curr_disc.binning_by_value:
                binning = "true"
            else:
                binning = "false"
            disc_to_return[str(x)] = {"MethodOfDiscretization": str(curr_disc.AbMethod),
                                      "BinsNumber": str(curr_disc.NumStates),
                                      "InterpolationGap": str(curr_disc.InterpolationGap),
                                      "PAAWindowSize": str(curr_disc.PAA), "BinningByValue": binning,
                                      "id": str(curr_disc.id)}
            x = x + 1
        x = 0
        karma_to_return = {"lengthNum": num}

        for karma in karma_arr:
            for curr_karma in karma:
                if curr_karma.index_same:
                    i_s = "true"
                else:
                    i_s = "false"
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
        to_return = {"disc": disc_to_return, "karma": karma_to_return}
        db.session.close()
        print(to_return)
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an eror!'}), 500


@app.route('/getUserName', methods=['GET'])
@token_required
def get_user_name(current_user):
    try:
        name = current_user.FName + " " + current_user.LName
        db.session.close()
        return jsonify({'Name': name})
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 403


@app.route('/getEmail', methods=['GET'])
@token_required
def get_email(current_user):
    try:
        email = current_user.Email
        print("get email request, email=" + email)
        db.session.close()
        return jsonify({'Email': email})
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 403


# this function asks for permission, it takes one argument in the url
# which is the name of the dataset like "dataset=datasetName"
@app.route('/askPermission', methods=['GET'])
@token_required
def ask_permission(current_user):
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
def load_mail(current_user):
    try:
        my_datasets = current_user.my_datasets
        to_return = {"myDatasets": {}, "myDatasetsLen": len(my_datasets)}
        print(str(len(my_datasets)))
        x = 0
        for curr_dataset in my_datasets:
            # full_name = current_user.FName + " " + current_user.LName
            curr_email = curr_dataset.Email
            to_return["myDatasets"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),
                                               "Owner": curr_email,
                                               "Category": curr_dataset.category,
                                               "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        users_permissions = Permissions.query.filter_by(Email=current_user.Email).all()
        to_return["myPermissions"] = {}
        to_return["myPermissionsLen"] = len(users_permissions)
        print(str(len(users_permissions)))
        x = 0
        for curr_record in users_permissions:
            curr_dataset = curr_record.dataset
            curr_email = curr_dataset.Email
            # full_name = current_user.FName + " " + current_user.LName
            to_return["myPermissions"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),
                                                  "Owner": curr_email,
                                                  "Category": curr_dataset.category,
                                                  "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        users_ask_permissions = ask_permissions.query.filter_by(Email=current_user.Email).all()
        to_return["askPermissions"] = {}
        to_return["askPermissionsLen"] = len(users_ask_permissions)
        print(str(len(users_ask_permissions)))
        x = 0
        for curr_record in users_ask_permissions:
            curr_dataset = curr_record.dataset
            curr_email = curr_dataset.Email
            print(str(curr_email))
            # full_name = current_user.FName + " " + current_user.LName
            to_return["askPermissions"][str(x)] = {"DatasetName": curr_dataset.Name, "Size": str(curr_dataset.size),
                                                   "Owner": curr_email,
                                                   "Category": curr_dataset.category,
                                                   "PublicPrivate": curr_dataset.public_private}
            x = x + 1
        to_return['Email'] = current_user.Email
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an error!'}), 500


# takes 2 arguments in the url, 'dataset' and 'userEmail' and gives a user a permission
@app.route('/acceptPermission', methods=['GET'])
@token_required
def accept_permission(current_user):
    try:
        dataset_name = request.args.get('dataset')
        user_email = request.args.get('userEmail')
        record = ask_permissions.query.filter_by(Email=user_email, name_of_dataset=dataset_name).first()
        user_email_check = record.dataset.owner.Email
        print("input email:" + user_email)
        print("db email:" + user_email_check)
        if current_user.Email != user_email_check:
            db.session.close()
            return jsonify({'message': 'dont try to fool me, you dont own this dataset!'}), 400
        to_add = Permissions(Email=user_email, name_of_dataset=dataset_name)
        db.session.add(to_add)
        db.session.delete(record)
        db.session.commit()
        db.session.close()
        return jsonify({'message': 'permission accepted!'})
    except:
        return jsonify({'message': 'there has been an error!'}), 500


# sends all the info about the data sets
@app.route('/getAllDataSets', methods=['GET'])
def get_all_datasets():
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
        return jsonify({'message': 'there has been an error!'}), 500


def check_exists(disc, epsilon, max_gap, verticale_support, num_relations, index_same, max_tirp_length):
    exists = karma_lego.query.filter_by(epsilon=epsilon, min_ver_support=verticale_support, num_relations=num_relations,
                                        max_gap=max_gap, max_tirp_length=max_tirp_length, index_same=index_same,
                                        discretization=disc).first()
    if exists is None:
        return False
    return True


def check_if_already_exists(dataset, paa, ab_method, num_states, interpolation_gap, gradient_file_name,
                            knowledge_based_file_name):
    exists = discretization.query.filter_by(dataset=dataset, PAA=paa, AbMethod=ab_method, NumStates=num_states,
                                            InterpolationGap=interpolation_gap,
                                            GradientFile_name=gradient_file_name,
                                            KnowledgeBasedFile_name=knowledge_based_file_name).first()
    if exists is None:
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


def delete_not_necessary(directory_path):
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            continue
        else:
            os.remove(filename)


@app.route('/addNewDisc', methods=['POST'])
@token_required
def add_new_disc(current_user):
    data = request.form
    PAA = int(data['PAA'])
    AbMethod = str(data['AbMethod'])
    NumStates = int(data['NumStates'])
    InterpolationGap = int(data['InterpolationGap'])
    dataset_name = str(data["datasetName"])
    binning = data["BinningByValue"]
    if binning == 'true':
        binning = True
    else:
        binning = False

    if 'GradientFile' not in data:
        GradientFile = request.files["GradientFile"]
        GradientFile.save(
            os.path.join(SERVER_ROOT, secure_filename(GradientFile.filename)))
        GradientFile_name = GradientFile.filename
    else:
        GradientFile_name = None
    if 'KnowledgeBasedFile' not in data:
        KnowledgeBasedFile = request.files["KnowledgeBasedFile"]
        KnowledgeBasedFile.save(os.path.join(SERVER_ROOT, secure_filename(KnowledgeBasedFile.filename)))
        KnowledgeBasedFile_name = KnowledgeBasedFile.filename
    else:
        KnowledgeBasedFile_name = None
    dataset1 = info_about_datasets.query.filter_by(Name=dataset_name).first()
    if check_if_already_exists(dataset1, PAA, AbMethod, NumStates, InterpolationGap, GradientFile_name,
                               KnowledgeBasedFile_name):
        return jsonify({'message': 'already exists!'}), 400
    disc_id = str(uuid.uuid4())
    disc = discretization(binning_by_value=binning, id=disc_id, dataset=dataset1, PAA=PAA, AbMethod=AbMethod,
                          NumStates=NumStates,
                          InterpolationGap=InterpolationGap, GradientFile_name=GradientFile_name,
                          KnowledgeBasedFile_name=KnowledgeBasedFile_name)
    db.session.add(disc)
    db.session.commit()
    create_directory_disc(dataset_name, disc_id)
    db.session.close()

    print("phew we are here...")

    # temporal-abstraction 'Path to dataset file' 'Path to output dir' per-property
    # -s (when using Gradient or KnowledgeBased) 'Path to states file' (when using Gradient or KnowledgeBased)
    # 'Path to Preprocessing file' 'Path to Temporal Abstraction file'

    # dataset_name = "sepsis"
    # disc_id = "119d401c-7109-4710-9a7d-a2c4f82ece78"
    dataset_path = SERVER_ROOT + '/' + dataset_name
    disc_path = SERVER_ROOT + '/' + dataset_name + '/' + disc_id

    config = defaultdict(empty_string)
    config["cli_path"] = " " + CLI_PATH
    config["dataset_or_property"] = " " + DATASET_OR_PROPERTY
    config["mode"] = " " + MODE
    config["dataset_path"] = " " + dataset_path + '/' + dataset_name + ".csv"
    config["output_dir"] = " " + disc_path
    config["output_dir_name"] = " " + disc_id
    config["preprocessing_path"] = " " + dataset_path + '/' + "preprocessing.csv"
    config["temporal_abstraction_path"] = " " + dataset_path + '/' + "temporal_abstraction.csv"

    run_hugobot(config)

    print("phew we are done?")

    # with zipfile.ZipFile('somePath/bla2.zip', 'r') as zip_ref:
    #    zip_ref.extractall('C:/Users/yonatan/PycharmProjects/HugoBotServer')
    return "success!"


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

    print(command)

    os.system(command)


def create_directory_for_dataset(dataset_name):
    try:
        os.mkdir(dataset_name)
    except OSError:
        print("Creation of the directory %s failed" % dataset_name)
    else:
        print("Successfully created the directory %s " % dataset_name)
    return dataset_name


def create_directory(dataset_name, discretization_id, kl_id):
    path = dataset_name + "/" + discretization_id + "/" + kl_id
    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)
    return path


def check_for_bad_user(kl, user_id):
    if kl.discretization.dataset.owner.Email == user_id:
        return False
    else:
        return True


def check_for_bad_user_disc(disc, user_id):
    if disc.dataset.owner.Email == user_id:
        return False
    else:
        return True


@app.route('/getTIM', methods=['POST'])
# @token_required
def get_TIM():
    try:
        data = request.form
        kl_id = data["kl_id"]
        class_num = data["class_num"]
        KL = karma_lego.query.filter_by(id=kl_id).first()
        # if (check_for_bad_user(KL, current_user.Email)):
        #  return jsonify({'message': 'dont try to fool me, you dont own it!'}), 403
        disc = KL.discretization.id
        dataset = KL.discretization.dataset.Name
        db.session.close()
        return send_file(SERVER_ROOT + "/" + dataset + '/' + disc + '/' + kl_id + '/' + class_num)
    except:
        db.session.close()
        return jsonify({'message': 'there is no such file to download'}), 404


@app.route('/getTIM1', methods=['GET', 'POST'])
def get_tim1():
    return send_file("C:/Users/Raz/PycharmProjects/hello.zip")


@app.route('/getDISC', methods=['POST'])
@token_required
def get_disc(current_user):
    print("hi0")
    data = request.form
    disc_id = data["disc_id"]
    disc = discretization.query.filter_by(id=disc_id).first()
    print("hi1")
    if check_for_bad_user_disc(disc, current_user.Email):
        return jsonify({'message': 'dont try to fool me, you dont own it!'}), 400
    print("hi2")
    dataset = disc.dataset.Name
    return send_file(dataset + '/' + disc_id + '/states.csv')


@app.route('/addTIM', methods=['POST'])
def add_TIM():
    try:
        data = request.form
        discretization_id = str(data['DiscretizationId'])
        if 'Epsilon' not in data:
            epsilon = int(0.0000)
        else:
            epsilon = int(data['Epsilon'])
        max_gap = int(data['Max Gap'])
        verticale_support = float(data['min_ver_support'])
        num_relations = int(data['num_relations'])
        max_tirp_length = int(data['max Tirp Length'])
        index_same = str(data['index_same'])
        if index_same == 'true':
            index_same = True
        else:
            index_same = False
        print(index_same)
        print(epsilon)
        disc = discretization.query.filter_by(id=discretization_id).first()
        email = disc.dataset.owner.Email
        if check_exists(disc, epsilon, max_gap, verticale_support, num_relations, index_same, max_tirp_length):
            return jsonify({'message': 'already exists!'}), 409
        dataset_name = get_dataset_name(disc)
        KL_id = str(uuid.uuid4())
        create_directory(dataset_name, discretization_id, KL_id)
        directory_path = dataset_name + "/" + discretization_id
        for filename in os.listdir(SERVER_ROOT + '/' + directory_path):
            if filename.endswith(".txt"):
                start_time = time.time()
                support_vec = verticale_support
                num_relations = num_relations
                max_gap = max_gap
                epsilon = epsilon
                max_tirp_length = max_tirp_length
                path = SERVER_ROOT + '/' + directory_path + '/' + filename
                out_path = SERVER_ROOT + '/' + directory_path + '/' + KL_id + '/' + filename
                print_output_incrementally = True
                entity_ids_num = 2
                index_same = index_same
                semicolon_end = True
                need_one_sized = True
                lego_0, karma_0 = RunKarmaLego.runKarmaLego(time_intervals_path=path, output_path=out_path,
                                                            index_same=index_same, epsilon=epsilon,
                                                            incremental_output=print_output_incrementally,
                                                            min_ver_support=support_vec,
                                                            num_relations=num_relations, skip_followers=False,
                                                            max_gap=max_gap, label=0,
                                                            max_tirp_length=max_tirp_length, num_comma=2,
                                                            entity_ids_num=entity_ids_num,
                                                            semicolon_end=semicolon_end, need_one_sized=need_one_sized)
                if not print_output_incrementally:
                    lego_0.print_frequent_tirps(out_path)
            else:
                continue
        KL = karma_lego(id=KL_id, epsilon=epsilon, min_ver_support=verticale_support, num_relations=num_relations,
                        max_gap=max_gap, max_tirp_length=max_tirp_length, index_same=index_same, discretization=disc)
        db.session.add(KL)
        db.session.commit()
        db.session.close()
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 404
    try:
        notify_by_email.send_an_email(message=f"Subject: karmalego created successfully", receiver_email=email)
        return jsonify({'message': 'karmalego created!'}), 200
    except:
        return jsonify({'message': 'cant send an email!'}), 409


# post reqeust that gets a json with 'Email',
# 'Nickname'(optional), 'Password', 'Lname', 'Fname'
@app.route('/register', methods=['POST'])
def create_user():
    try:
        data = request.form
        double_user = Users.query.filter_by(Email=data['Email']).first()
        if double_user:
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
    # try:
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
        return jsonify({'message': 'problem with data 1'}), 400
    # except:
    #     db.session.close()
    #     return jsonify({'message': 'problem with data 2'}), 400


@app.route("/")
@app.route("/home")
def home():
    return "<h1>Home Page</h1>"


@app.route("/about")
def about():
    return "<h1>About Page</h1>"


@app.route("/stepone", methods=["POST"])
@token_required
def upload_stepone(current_user):
    # try:
    print(current_user)
    # Dataset File: user input
    raw_data_file = request.files['file']

    # Now, save the info as a tuple in the DB and the file as part of the file system:
    # info_about_datasets tuple:
    # Name (PK), Pub_date, Description, Rel_path, Public/private, Category, Size, Views, Downloads, Email

    # Name: user input
    dataset_name = request.form['datasetName']

    # Pub_date: generated (get current time)

    # Description: user input
    description = request.form['description']

    # Rel_path: generated (using user input - the name of the directory is the dataset name)
    # rel_path = os.path.join('C:/Users/Raz/PycharmProjects/HugoBotServer', dataset_name, raw_data_file.filename)

    # Public/private: user input
    public_private = request.form['publicPrivate']

    # Category: user input
    category = request.form['category']

    # Size: generated (calculated from file)
    # size = os.path.getsize(
    #     os.path.join('C:/Users/Raz/PycharmProjects/HugoBotServer', dataset_name, raw_data_file.filename))

    # source: user input
    dataset_source = request.form['datasetSource']

    # Views: generated (instantiated to 0)
    # views = "0"

    # Downloads: generated (instantiated to 0)
    # downloads = "0"

    # Email: user input (identifier of the user)
    # email = "3"

    # Validate dataset file integrity

    # Save the dataset file

    print(dataset_name)
    create_directory_for_dataset(dataset_name)
    raw_data_file.save(
        os.path.join(SERVER_ROOT, dataset_name, secure_filename(raw_data_file.filename)))

    # rel_path=rel_path,
    # pub_date=pub_date,

    dataset1 = info_about_datasets(Name=dataset_name, Description=description, source=dataset_source,
                                   public_private=public_private, category=category, size=8.54, views=0,
                                   downloads=0, owner=current_user)
    db.session.add(dataset1)
    db.session.commit()

    # db.session.rollback()
    # db.session.close()
    # return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'Dataset Successfully Validated!'})


@app.route("/steptwo", methods=["POST"])
@token_required
def upload_steptwo(current_user):
    try:
        file = request.files['file']
        print(file)
        dataset_name = request.form['datasetName']
        print(dataset_name)
        file.save(
            os.path.join(SERVER_ROOT, dataset_name, secure_filename(file.filename)))
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'VMap Registered Successfully!'})


@app.route("/steptwocreate", methods=['POST'])
@token_required
def step_two_create(current_user):
    try:
        file = request.form['csv']
        # needs additional work
        print(file)
        dataset_name = request.form['datasetName']
        print(dataset_name)
        # file.save(os.path.join(SERVER_ROOT,dataset_name, secure_filename(file.filename)))
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'VMap Registered Successfully!'})


@app.route("/stepthree", methods=["POST"])
@token_required
def upload_stepthree(current_user):
    try:
        file = request.files['file']
        print(file)
        dataset_name = request.form['datasetName']
        print(dataset_name)
        file.save(
            os.path.join(SERVER_ROOT, dataset_name, secure_filename(file.filename)))
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
    return jsonify({"Name": "sepsis",
                    "category": "sports",
                    "owner_name": "yonatan shaya",
                    "source": "raz himself",
                    "Description": "the sepsis dataset",
                    "size": "8.54 MB",
                    "views": "17",
                    "downloads": "2"}), 200


@app.route("/getVMapFile", methods=["GET"])
def get_vmap_file():
    dataset_name = request.args.get("id")
    print(dataset_name)
    return send_file(dataset_name + '/' + 'VMap.csv'), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)
