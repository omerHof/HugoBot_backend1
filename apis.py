import check_email
from collections import defaultdict
import csv
import datetime
import filecmp
from flask import Flask, request, jsonify, make_response, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from itertools import islice
import jwt
from KarmaLego_Framework import RunKarmaLego
import notify_by_email
import os
import sys
import time
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import zipfile

from ofirstudents import TemporalWindowsCreation

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# <editor-fold desc="Server Constant Definition">
SERVER_ROOT = "C://HugoBot/Production/HugoBotServer"
DATASETS_ROOT = SERVER_ROOT + '/Datasets'
RAW_DATA_HEADER_FORMAT = ["EntityID", "TemporalPropertyID", "TimeStamp", "TemporalPropertyValue"]
VMAP_HEADER_FORMAT = ["Variable ID", "Variable Name", "Description"]
VMAP_HEADER_FORMAT_2 = ["TemporalPropertyID", "TemporalPropertyName", "Description"]
GRADIENT_HEADER_FORMAT = ["StateID", "TemporalPropertyID", "Method", "BinID", "BinLow", "BinHigh", "BinLowScore"]
KB_HEADER_FORMAT = ["StateID", "TemporalPropertyID", "TemporalPropertyName",
                    "Method", "BinID", "BinLow", "BinHigh", "BinLowScore", "BinLabel"]
HUGOBOT_EXECUTABLE_PATH = "HugoBot-beta-release-v1.1.5_03-01-2020/cli.py"
CLI_PATH = SERVER_ROOT + '/' + HUGOBOT_EXECUTABLE_PATH
MODE = "temporal-abstraction"
DATASET_OR_PROPERTY = "per-dataset"
PAA_FLAG = "-paa"
DISCRETIZATION_PREFIX = "discretization"
GRADIENT_PREFIX = "gradient"
GRADIENT_FLAG = "-sp"
KB_PREFIX = "knowledge-based"
ABSTRACTION_METHOD_CONVERSION = {
    'Equal Frequency': 'equal-frequency',
    'Equal Width': 'equal-width',
    'SAX': 'sax',
    'Persist': 'persist',
    'KMeans': 'kmeans',
    'Knowledge-Based': 'knowledge-based',
    'Gradient': 'gradient',
    'TD4C-Cosine': 'td4c-cosine',
    'TD4C-Diffmax': 'td4c-diffmax',
    'TD4C-Diffsum': 'td4c-diffsum',
    'TD4C-Entropy': 'td4c-entropy',
    'TD4C-Entropy-IG': 'td4c-entropy-ig',
    'TD4C-SKL': 'td4c-skl'
}


# </editor-fold>


# <editor-fold desc="DB ORM">
class Users(db.Model):
    """
    This is the Users Table.
    It is in charge of maintaining data on Users, with the User's Email address as its Primary Key.
    """
    Email = db.Column(db.String(80), primary_key=True)
    institute = db.Column(db.String(50), nullable=False)
    degree = db.Column(db.String(10), nullable=False)
    Password = db.Column(db.String(80), nullable=False)
    FName = db.Column(db.String(50), nullable=False)
    LName = db.Column(db.String(50), nullable=False)
    my_datasets = db.relationship('info_about_datasets', backref='owner', lazy='subquery')
    Permissions = db.relationship('Permissions', backref='owner', lazy='subquery')
    ask_permissions = db.relationship('ask_permissions', backref='owner', lazy='subquery')


class info_about_datasets(db.Model):
    """
    This table is in charge of holding metadata on Datasets in the system, with the Dataset's name as its Primary Key.
    Information such as the Dataset's description or categorization goes here,
    while the content itself (the actual data etc.) is stored systematically in the "Datasets" folder
    """
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


class Permissions(db.Model):
    """
    This table holds all the permissions in the system.
    It represents a Many-To-Many relationship between the Users table and the info_about_datasets table,
      with [Email,Dataset_Name] as its Composite Key.
    The existence of a tuple t such that t.Email = e and t.name_of_dataset = d signifies that e has permission to use d.
    """
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50), db.ForeignKey('info_about_datasets.Name'), primary_key=True)


class ask_permissions(db.Model):
    """
    This table holds all the permission requests in the system.
    It represents a Many-To-Many relationship between the Users table and the info_about_datasets table,
        with [Email,Dataset_Name] as its Composite Key.
    The existence of a tuple t such that t.Email = e and t.name_of_dataset = d
        signifies that e has asked for permission to use d.
    """
    Email = db.Column(db.String(30), db.ForeignKey('users.Email'), primary_key=True)
    name_of_dataset = db.Column(db.String(50), db.ForeignKey('info_about_datasets.Name'), primary_key=True)


class discretization(db.Model):
    """
    This table holds all the info about the discretizations.
    Its primary key is a unique Discretization ID.
    In case we are dealing with a Gradient/Knowledge-based discretization,
    the files themselves are checked for uniqueness.
    The files of the discretization itself (states file, KL input file etc.) are stored systematically,
    in "Datasets/<Dataset Name>/<Disc Id>/".
    """
    id = db.Column(db.String(150), primary_key=True)
    PAA = db.Column(db.Integer, nullable=False)
    AbMethod = db.Column(db.String(25), nullable=False)
    NumStates = db.Column(db.Integer, nullable=False)
    InterpolationGap = db.Column(db.Integer, nullable=False)
    KnowledgeBasedFile_name = db.Column(db.String(120))
    GradientFile_name = db.Column(db.String(120))
    GradientWindowSize = db.Column(db.Integer, nullable=False)
    Finished = db.Column(db.Boolean, nullable=False)
    karma_lego = db.relationship('karma_lego', backref='discretization', lazy='subquery')
    dataset_Name = db.Column(db.String(150), db.ForeignKey('info_about_datasets.Name'), nullable=False)


class karma_lego(db.Model):
    """
    This table holds all the info about the KarmaLego runs.
    Its primary key is a unique KarmaLego ID
    The output file(s) is/are stored separately in "Datasets/<Dataset Name>/<Disc Id>/<KL Id>/".
    """
    id = db.Column(db.String(150), primary_key=True)
    epsilon = db.Column(db.Float)
    min_ver_support = db.Column(db.Float, nullable=False)
    num_relations = db.Column(db.Integer, nullable=False)
    max_gap = db.Column(db.Integer, nullable=False)
    max_tirp_length = db.Column(db.Integer, nullable=False)
    index_same = db.Column(db.Boolean, nullable=False)
    Finished = db.Column(db.Boolean, nullable=False)
    discretization_name = db.Column(db.String(150), db.ForeignKey('discretization.id'), nullable=False)


# </editor-fold>


def token_required(f):
    """
    this function checks if the user is connected by checking the token
    :param f: the token
    :return:
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # if the token is correct
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        print(token)

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(Email=data['Email']).first()
        #if something went wrong
        except:
            db.session.close()
            print("token invalid. client rejected.")
            return jsonify({'message': 'Token is invalid!'}), 401
        db.session.close()
        return f(current_user, *args, **kwargs)

    return decorated


def empty_string():
    """
    This function defines an empty string.
    It is used as a default fallback in the default dict in the add_new_disc method.
    :return: an empty string
    """
    return ""


# <editor-fold desc="DB Utils">
def check_for_authorization(current_user, dataset_name):
    """
    This function verifies the authorization of the current user on a given dataset.
    she gets the current user by his id and the dataset name
    :param current_user: the email of the current user
    :param dataset_name: the name of the dataset
    :return:
    """
    per = Permissions.query.filter_by(name_of_dataset=dataset_name, Email=current_user.Email).first()
    dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
    if dataset.public_private == "Public":
        return False

    if (per is None or current_user.Email != per.owner.Email) and (dataset.owner.Email != current_user.Email):
        return True
    else:
        return False


def check_exists(disc, epsilon, max_gap, vertical_support, num_relations, index_same, max_tirp_length):
    """
    This function checks if a KL run already exists in the DB
    param - epsilon - the value of epsilon, int
    param - max gap- int, the max_gap between the intervals for creating the index
    :param min_ver_support: float, the minimum vertical support value
    :param num_relations: int, number of relations
    :param index_same: Boolean, index same symbols or not
    :return:
    if there is already a kl with that caracteristics
    """
    exists = karma_lego.query.filter_by(
        discretization=disc,
        epsilon=epsilon,
        index_same=index_same,
        max_gap=max_gap,
        max_tirp_length=max_tirp_length,
        min_ver_support=vertical_support,
        num_relations=num_relations).first()
    if exists is None:
        return False
    return True



def check_if_already_exists(dataset, paa, ab_method, num_states, interpolation_gap, gradient_file_name,
                            knowledge_based_file_name):
    """
    This function checks if a discretization run already exists in the DB
    :param PAA
    :param NumStates - the number of states we want to send to discretization, int
    :param InterpolationGap - the interpolation gap variable we want to send to discretization , float
    :param AbMethod - the abstruct mathod we want to send to discretization, string
    :param KnowledgeBasedFile - if there is a knowledge-based file we send it as well, csv file
    :param GradientFile - if there is a gradiente file we send it as well, csv file
    :param GradientWindowSize - if there is a gradient file we send its window size, float
    :return:
    if there is already a discretization with that caracteristics
    """
    exists = discretization.query.filter_by(
        AbMethod=ab_method,
        dataset=dataset,
        GradientFile_name=gradient_file_name,
        InterpolationGap=interpolation_gap,
        KnowledgeBasedFile_name=knowledge_based_file_name,
        NumStates=num_states,
        PAA=paa).first()
    if exists is None:
        return False
    return True


def check_for_bad_user_disc(disc, user_id):
    """
    This function verifies whether or not the owner of the current discretization's dataset is the current user
    :param disc: discretization id
    :param user_id: his email
    :return:
    wether the user validated or not
    """
    if disc.dataset.owner.Email == user_id:
        return False
    else:
        return True



def check_for_bad_user(kl, user_id):
    """
    This function verifies whether or not the owner of the current KL run's dataset is the current user.
    :param kl: the id of the karma lego run
    :param user_id: the email of the user
    :return:
    wether the user validated or not
    """
    if kl.discretization.dataset.owner.Email == user_id:
        return False
    else:
        return True


# </editor-fold>


# <editor-fold desc="File System Utils">

def create_directory_disc(dataset_name, discretization_id):
    """
    This function creates a directory for a discretization inside its parent dataset folder.
    :param dataset_name: the name of the dataset
    :param discretization_id: the id of the discretization
    :return:
    the path to the directory we created
    """
    path = DATASETS_ROOT + '/' + dataset_name + "/" + discretization_id
    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)
    return path



def create_directory_for_dataset(dataset_name):
    """
    This function creates a directory for a dataset.
    :param dataset_name: the name of the dataset, string
    :return:
    the name of the dataset
    """
    try:
        os.mkdir(os.path.join(DATASETS_ROOT, dataset_name))
    except OSError:
        print("Creation of the directory %s failed" % dataset_name)
    else:
        print("Successfully created the directory %s " % dataset_name)
    return dataset_name


def create_directory(dataset_name, discretization_id, kl_id):
    """
    This function creates a directory for a KarmaLego run inside its parent discretization folder.
    :param dataset_name: the name of the datset
    :param discretization_id: the id of the discretization
    :param kl_id: the id of the karma lego run
    :return:
    """
    path = DATASETS_ROOT + '/' + dataset_name + "/" + discretization_id + "/" + kl_id
    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)
    return path


def create_disc_zip(disc_path, zip_name, files_to_zip):
    """
    This function creates a zipped file from a list of files in a desired directory
    :param disc_path: the path of the discretization
    :param zip_name: the name we want the zipped file to have in the end
    :param files_to_zip: a list of the files we want to include in the zip
    :return:
    """
    with zipfile.ZipFile(os.path.join(disc_path, zip_name), mode='w') as zipped_disc:
        for file in files_to_zip:
            file_path = os.path.join(disc_path, file)
            zipped_disc.write(file_path, os.path.basename(file_path))

# currently not in any use
def unzip(from_path, to_path, file_name):
    with zipfile.ZipFile(from_path + '/' + file_name, 'r') as zip_ref:
        zip_ref.extractall(to_path)

# currently not in any use
def delete_not_necessary(directory_path):
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            continue
        else:
            os.remove(filename)


# </editor-fold>


# <editor-fold desc="Users Module">
@app.route('/register', methods=['POST'])
def create_user():
    """
    This route handles registration of a new user in the system
    :param firstName- the firstname of the user, string
    :param lastName - the last name of the user, string
    :param institute - his institue, string
    :param degree - his degree, string
    :param - his email, string
    :param pass - the password that he wants for himself, string
    :return:
    400 (BAD REQUEST) if:
    # the email is not valid
    # the email already exists
    # an unexpected error occurred

    409 (CONFLICT) if:
    # the server cannot send an email

    200 (OK) if everything went good
    """
    try:
        data = request.form
        if check_email.check(data['Email']):
            return jsonify({'message': 'email is not valid'}), 400
        double_user = Users.query.filter_by(Email=data['Email']).first()
        if double_user:
            db.session.close()
            print("hello")
            return jsonify({'message': 'there is already a user with that Email'}), 400
        hashed_password = generate_password_hash(data['Password'], method='sha256')
        new_user = Users(
            degree=data["Degree"],
            Email=data['Email'],
            FName=data['Fname'],
            institute=data["Institute"],
            LName=data['Lname'],
            Password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        try:
            notify_by_email.send_an_email(
                message=f"Subject: registration successfully completed",
                receiver_email=data['Email'])
        except:
            return jsonify({'message': 'cannot send email!.'}), 409
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'New user created!'})

@app.route('/createTmpWindows', methods=['POST'])
def createTmpWindows():
    data = request.form
    #data['Password']

    datasetName = data['datasetName']

    TemporalWindowsCreation.TemporalWindowsCreation(int(data['observation']),
                            int(data['predictionPeriod']),
                            int(data['overlap']),
                            SERVER_ROOT+ '/Datasets/' +datasetName + '/' +datasetName + '.csv',
                            SERVER_ROOT + '/Datasets/' + datasetName ,
                            StudyDesign=data['studyDesign'],
                            positiveNegativeRatio=(int(data['positiveRatio']), int(data['negativeRatio'])),
                            casePositive=int(data['positiveWindows']),
                            caseNegative=int(data['negativeWindowsCase']),
                            controlNegative=int(data['negativeWindowsControl']))

    return jsonify({'message': 'New user created!'})



@app.route('/login', methods=['POST'])
def login():
    """
    This route handles a login attempt of an apparent user to the system
    send with key value like x-access-token in the header
    :param: Email - the email of the user, string
    :param: password: the password of the user
    :return:
    400 (BAD REQUEST) if:
    # one of the fields was left empty
    # the email is incorrect
    # the password doesn't match the email

    200 (OK) if everything went good, also returns a token (jwt) that allows a user access to the website
    """
    try:
        data = request.form
        if 'Email' not in data or 'Password' not in data:
            return make_response('you didnt give me Email or Password', 400)
        user = Users.query.filter_by(Email=data['Email']).first()
        print(user)
        if not user:
            db.session.close()
            return make_response({'message': 'Email is not correct'}, 400)
        if check_password_hash(user.Password, data['Password']):
            token = jwt.encode(
                {'Email': user.Email, 'exp': (datetime.datetime.utcnow() + datetime.timedelta(minutes=3000))},
                app.config['SECRET_KEY'], algorithm='HS256')
            db.session.close()
            return jsonify({'token': token.decode('UTF-8')})
        else:
            db.session.close()
            return jsonify({'message': 'wrong password'}), 400
    except:
        db.session.close()
        return jsonify({'message': 'Wrong Email!'}), 400


# </editor-fold>


# <editor-fold desc="Mail Module">
@app.route('/loadMail', methods=['GET'])
@token_required
def load_mail(current_user):
    """
    This function loads all of the relevant mail relative to the current user (= the user who sent the request).
    :param current_user: The currently logged in user.
    :return:
    500 (INTERNAL SERVER ERROR) if:
    # The server experienced an unintended internal error.

    200 (OK) if all went well, the response contains:
    # myDatasets: A table containing all of the user's datasets.
    # myDatasetsLen: The length of myDatasets.
    # tablesToExplore: A table containing every dataset a user can ask permission to use.
    # tablesToExploreLen: the length of tablesToExplore.
    # myPermissions: A table of datasets for which the current user has permissions.
    # myPermissionsLen: the length of myPermissions
    # askPermissions: A table of datasets for which the current user has requested (but not yet granted) permissions.
    # askPermissionsLen: the length of askPermissions
    # approve A table of datasets that the user owns for which certain users have asked permission for.
    # approveLen: the length of approve
    """
    try:
        #loads my datasets
        my_datasets = current_user.my_datasets
        to_return = {"myDatasets": {}, "myDatasetsLen": len(my_datasets)}
        print(str(len(my_datasets)))
        x = 0
        for curr_dataset in my_datasets:
            # full_name = current_user.FName + " " + current_user.LName
            curr_email = curr_dataset.Email
            to_return["myDatasets"][str(x)] = {
                "Category": curr_dataset.category,
                "DatasetName": curr_dataset.Name,
                "Owner": curr_email,
                "PublicPrivate": curr_dataset.public_private,
                "Size": str(curr_dataset.size)}
            x = x + 1
        datasets = info_about_datasets.query.all()
        #loads all the tables we can explore
        to_return["tablesToExplore"] = {}
        x = 0
        for curr_dataset in datasets:
            print(curr_dataset.public_private)
            if curr_dataset.public_private != 'Public':
                full_name = curr_dataset.owner.FName + " " + curr_dataset.owner.LName
                to_return["tablesToExplore"][str(x)] = {
                    "Category": curr_dataset.category,
                    "DatasetName": curr_dataset.Name,
                    "Owner": full_name,
                    "PublicPrivate": curr_dataset.public_private,
                    "Size": str(curr_dataset.size)}
                x = x + 1
        # loads all the tables we have permission for
        to_return["tablesToExploreLen"] = x
        users_permissions = Permissions.query.filter_by(Email=current_user.Email).all()
        to_return["myPermissions"] = {}
        to_return["myPermissionsLen"] = len(users_permissions)
        print(str(len(users_permissions)))
        x = 0
        for curr_record in users_permissions:
            curr_dataset = curr_record.dataset
            curr_email = curr_dataset.Email
            # full_name = current_user.FName + " " + current_user.LName
            to_return["myPermissions"][str(x)] = {
                "Category": curr_dataset.category,
                "DatasetName": curr_dataset.Name,
                "Owner": curr_email,
                "PublicPrivate": curr_dataset.public_private,
                "Size": str(curr_dataset.size)}
            x = x + 1
        # loads all the permissions we want to get
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
            to_return["askPermissions"][str(x)] = {
                "Category": curr_dataset.category,
                "DatasetName": curr_dataset.Name,
                "Owner": curr_email,
                "PublicPrivate": curr_dataset.public_private,
                "Size": str(curr_dataset.size)}
            x = x + 1

        # laods all the permissions we already got
        ask_me = ask_permissions.query.all()
        to_return["approve"] = {}
        x = 0
        counter = 0
        for curr_record in ask_me:
            curr_dataset = curr_record.dataset
            curr_email = curr_dataset.Email
            if curr_email == current_user.Email:
                # full_name = current_user.FName + " " + current_user.LName
                to_return["approve"][str(x)] = {
                    "Category": curr_dataset.category,
                    "DatasetName": curr_dataset.Name,
                    "Grantee": curr_record.Email,
                    "Owner": curr_email,
                    "PublicPrivate": curr_dataset.public_private,
                    "Size": str(curr_dataset.size)}
                counter = counter + 1
                x = x + 1
        to_return["approveLen"] = counter
        to_return['Email'] = current_user.Email
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an error!'}), 500


# this function asks for permission, it takes one argument in the url
# which is the name of the dataset like "dataset=datasetName"
@app.route('/askPermission', methods=['GET'])
@token_required
def ask_permission(current_user):
    """
    This function handles a permission request for a dataset by the current user.
    :param current_user: The currently logged in user.
    :param dataset: witch dataset we want permission
    :return:
    400 (BAD REQUEST) if:
    # The server experienced an unintended internal error.

    409 (CONFLICT) if:
    # An Email about the request could not be sent to the owner.

    200 (OK) if all went well.
    """
    try:
        dataset_name = request.args.get('dataset')
        dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
        owner_email = dataset.owner.Email
        ask1 = ask_permissions(Email=current_user.Email, name_of_dataset=dataset_name)
        db.session.add(ask1)
        db.session.commit()
        try:
            notify_by_email.send_an_email(
                message=f"Subject: A user with the email "
                        + current_user.Email
                        + " has asked for permission to use \""
                        + dataset_name + "\"",
                receiver_email=owner_email)
        except:
            return jsonify({'message': 'cannot send an email!'}), 409
        db.session.close()

        return jsonify({'message': 'permission asked!'})
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400


# takes 2 arguments in the url, 'dataset' and 'userEmail' and gives a user a permission
@app.route('/acceptPermission', methods=['GET'])
@token_required
def accept_permission(current_user):
    """
    This function handles a permission acceptance for a dataset owned by the current user.
    :param current_user: The currently logged in user.
    param dataset: the name of the dataset to accept, string
    paran userEmail: the email of the user that we want to accept his permission
    :return:
    400 (BAD REQUEST) if:
    # The current user does not own the dataset he is trying to give permission for.

    409 (CONFLICT) if:
    # An Email about the acceptance could not be sent to the grantee.

    500 (INTERNAL SERVER ERROR) if:
    # The server experienced an unintended internal error.

    200 (OK) if all went well.
    """
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
        try:
            notify_by_email.send_an_email(
                message=f"Subject: You got permission for Dataset " + dataset_name,
                receiver_email=user_email)
        except:
            return jsonify({'message': 'cannot send email!.'}), 409
        return jsonify({'message': 'permission accepted!'})
    except:
        return jsonify({'message': 'there has been an error!'}), 500


# takes 2 arguments in the url, 'dataset' and 'userEmail' and removes a user's permission request
@app.route('/rejectPermission', methods=['GET'])
@token_required
def reject_permission(current_user):
    """
    This function handles a permission rejection for a dataset owned by the current user.
    :param current_user: The currently logged in user.
    param dataset: the name of the dataset to reject, string
    paran userEmail: the email of the user that we want to reject his permission
    :return:
    400 (BAD REQUEST) if:
    # The current user does not own the dataset he is trying to deny permission to.

    409 (CONFLICT) if:
    # An Email about the rejection could not be sent to the grantee.

    500 (INTERNAL SERVER ERROR) if:
    # The server experienced an unintended internal error.

    200 (OK) if all went well.
    """
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
        db.session.delete(record)
        db.session.commit()
        db.session.close()
        try:
            notify_by_email.send_an_email(
                message=f"Subject: Your permission request for Dataset " + dataset_name + " was rejected",
                receiver_email=user_email)
        except:
            return jsonify({'message': 'cannot send email!.'}), 409
        return jsonify({'message': 'permission accepted!'})
    except:
        return jsonify({'message': 'there has been an error!'}), 500


# </editor-fold>


# <editor-fold desc="Validations">
def check_non_negative_int(s):
    """
    Validates that the input string represents an integer larger than or equal to 0.
    :param s: the string we want to check
    :return: True if it is represents an integer larger than or equal to 0, False otherwise
    """
    try:
        return int(s) >= 0
    except ValueError:
        return False


def check_int(s):
    """
    Validates that the input string represents an integer.
    :param s: the string we want to check
    :return: True if it is represents an integer, False otherwise
    """
    try:
        int(s)
        return True
    except ValueError:
        return False


def check_float(s):
    """
    Validates that the input string represents an floating point number.
    :param s: the string we want to check
    :return: True if it is represents an floating point number, False otherwise
    """
    try:
        float(s)
        return True
    except ValueError:
        return False


def validate_raw_data_header(raw_data_path):
    """
    Validates that the header of a user-submitted raw data file adheres to HugoBot's standards.
    :param raw_data_path: a path to the raw data file
    :return: True if the header fits the format, False otherwise
    """
    with open(raw_data_path) as data:
        reader = csv.reader(data, delimiter=',')
        for header in islice(reader, 0, 1):

            # solves a utf-8-bom encoding issue where ï»¿ gets added in the beginning of .csv files.
            entity_id_to_compare = header[0].replace("ï»¿", "")

            if len(header) == len(RAW_DATA_HEADER_FORMAT):
                if RAW_DATA_HEADER_FORMAT[0] in entity_id_to_compare:
                    if header[1] == RAW_DATA_HEADER_FORMAT[1]:
                        if header[2] == RAW_DATA_HEADER_FORMAT[2]:
                            if header[3] == RAW_DATA_HEADER_FORMAT[3]:
                                return True
            return False


def validate_raw_data_body(raw_data_path):
    """
    Validates the integrity of the data in the raw data file itself.
    :param raw_data_path: a path to the raw data file
    :return: True if every row:
    # Has a non-negative integer as its 1st element
    # Has an integer as its 2nd element
    # Has a non-negative integer as its 3rd element
    # Has a floating point number as its 4th element
    False otherwise
    """
    with open(raw_data_path) as data:
        reader = csv.reader(data, delimiter=',')
        i = 0
        flag = True
        for row in reader:
            if i == 0:
                i = i + 1
                continue
            flag &= check_non_negative_int(row[0])
            flag &= check_int(row[1])
            flag &= check_non_negative_int(row[2])
            flag &= check_float(row[3])
            i = i + 1
        return flag


def get_variable_list(data_path, column):
    """
    Receives a path to a raw data file and a column and extracts a list of unique values in that column
    :param data_path: a path to the raw data file
    :param column: the column which we want to get unique values from
    :return: a list of all unique value
    """
    try:
        with open(data_path) as data:
            variable_list = []
            reader = csv.reader(data, delimiter=',')
            for row in reader:
                variable_list.append(row[column])
            variable_list = variable_list[1:]  # truncate header
            variable_list = list(set(variable_list))  # remove duplicates
            data.close()
            return variable_list
    except (IOError, PermissionError):
        return []


def get_variable_map(vmap_path):
    """
    Receives a path to a variable map file and returns a dictionary that maps each id to its name (both are unique)
    :param vmap_path: a path to the variable map file
    :return: a <string,string> dictionary that maps IDs to names
    """
    try:
        with open(vmap_path) as vmap:
            variable_dic = {}
            reader = csv.reader(vmap, delimiter=',')
            i = 0
            for row in reader:
                if i == 0:
                    # ignore header
                    i = i + 1
                    continue
                variable_dic[row[0]] = row[1]
            vmap.close()
            return variable_dic
    except (FileNotFoundError, IOError, PermissionError):
        return {}


def validate_vmap_header(vmap_path):
    """
    Validates that the header of a user-submitted variable map file adheres to HugoBot's standards.
    :param vmap_path: a path to the variable map file
    :return: True if the header fits one of the formats, False otherwise
    """
    with open(vmap_path) as vmap:
        reader = csv.reader(vmap, delimiter=',')
        for header in islice(reader, 0, 1):

            # solves a utf-8-bom encoding issue where ï»¿ gets added in the beginning of .csv files.
            variable_id_to_compare = header[0].replace("ï»¿", "")

            if len(header) == len(VMAP_HEADER_FORMAT):
                if VMAP_HEADER_FORMAT[0] in variable_id_to_compare:
                    if header[1] == VMAP_HEADER_FORMAT[1]:
                        if header[2] == VMAP_HEADER_FORMAT[2]:
                            return True

            if len(header) == len(VMAP_HEADER_FORMAT_2):
                if VMAP_HEADER_FORMAT_2[0] in variable_id_to_compare:
                    if header[1] == VMAP_HEADER_FORMAT_2[1]:
                        if header[2] == VMAP_HEADER_FORMAT_2[2]:
                            return True
            return False


def validate_id_integrity(raw_data_path, vmap_path):
    """
    Validates whether or not a user has attended to each and every variable in the raw data file
     in his submitted variable map file.
    :param raw_data_path: a path to the raw data file
    :param vmap_path: a path to the variable map file
    :return: True if the list of variables match, False otherwise
    """
    raw_data_variable_list = get_variable_list(raw_data_path, 1)
    vmap_variable_list = get_variable_list(vmap_path, 0)
    return sorted(raw_data_variable_list) == sorted(vmap_variable_list)


def validate_entity_id_integrity(raw_data_path, entity_path):
    """
    Validates whether or not a user has attended to each and every entity in the raw data file
     in his submitted entity file.
    :param raw_data_path: a path to the raw data file
    :param entity_path: a path to the entity file
    :return: True if the list of entities match, False otherwise
    """
    raw_data_entity_list = get_variable_list(raw_data_path, 0)
    entity_list = get_variable_list(entity_path, 0)
    return sorted(raw_data_entity_list) == sorted(entity_list)


def validate_gradient_file_header(gradient_file_path):
    """
    Validates that the header of a user-submitted gradient discretization file's header adheres to HugoBot's standards.
    :param gradient_file_path: a path to the gradient file
    :return: True if the header fits one of the formats, False otherwise
    """
    with open(gradient_file_path) as gradient_file:
        reader = csv.reader(gradient_file, delimiter=',')
        for header in islice(reader, 0, 1):

            # solves a utf-8-bom encoding issue where ï»¿ gets added in the beginning of .csv files.
            state_id_to_compare = header[0].replace("ï»¿", "")

            if len(header) <= 7 and GRADIENT_HEADER_FORMAT[0] in state_id_to_compare:
                if header[1] == GRADIENT_HEADER_FORMAT[1]:
                    if header[2] == GRADIENT_HEADER_FORMAT[2]:
                        if header[3] == GRADIENT_HEADER_FORMAT[3]:
                            if header[4] == GRADIENT_HEADER_FORMAT[4]:
                                if header[5] == GRADIENT_HEADER_FORMAT[5]:
                                    if len(header) == 6 or header[6] == GRADIENT_HEADER_FORMAT[6]:
                                        return True
            return False


def validate_gradient_file_body(gradient_file_path):
    """
    Validates that the header of a user-submitted gradient discretization file's body
    adheres to HugoBot's standards.
    :param gradient_file_path: a path to the gradient file
    :return: True if every row:
    # Has a non-negative integer as its 1st element
    # Has a non-negative integer as its 2nd element
    # Has 'gradient' as the 3rd element
    # Has a non-negative integer as its 4th element
    # Has a floating point number between -90 and 90 as its 5th element
    # Has a floating point number between -90 and 90 as its 6th element
    False otherwise
    """
    with open(gradient_file_path) as gradient_file:
        reader = csv.reader(gradient_file, delimiter=',')

        i = 0
        flag = True
        for row in reader:
            if i == 0:
                i = i + 1
                continue

            flag &= check_non_negative_int(row[0])
            flag &= check_non_negative_int(row[1])
            flag &= (row[2] == "gradient")
            flag &= check_non_negative_int(row[3])
            flag &= check_float(row[4]) and (float(row[4]) >= -90) and (float(row[4]) <= 90)
            flag &= check_float(row[5]) and (float(row[5]) >= -90) and (float(row[5]) <= 90)

            i = i + 1

    return flag


def validate_uniqueness(dataset_path, file_name, path_to_exclude):
    """
    Validates a submitted gradient/knowledge-based file hasn't already been submitted to the system.
    :param dataset_path: The path to the dataset which we want to perform temporal abstraction on.
    :param file_name: The name of the file we want to verify the uniqueness of (e.g states_kb.csv)
    :param path_to_exclude: The path to the current file (it's trivial that curr_file = curr_file...)
    :return: True if the file is unique, False otherwise
    """
    walker = os.walk(dataset_path)
    existing_discs = [x[1] for x in walker][0]

    for disc in existing_discs:
        disc_path = os.path.join(dataset_path, disc)
        path_to_compare = os.path.join(disc_path, file_name)
        if path_to_compare == path_to_exclude:  # of course the file is equal to itself
            continue
        if not os.path.exists(path_to_compare):  # if the current disc is not a gradient/kb disc, then skip it
            continue
        if filecmp.cmp(path_to_exclude, path_to_compare):
            return False

    return True


def validate_kb_file_header(kb_file_path):
    """
    Validates that the header of a user-submitted knowledge-based discretization file's header
    adheres to HugoBot's standards.
    :param kb_file_path: a path to the knowledge-based file
    :return: True if the header fits the format, False otherwise
    """
    with open(kb_file_path) as kb_file:
        reader = csv.reader(kb_file, delimiter=',')
        for header in islice(reader, 0, 1):

            # solves a utf-8-bom encoding issue where ï»¿ gets added in the beginning of .csv files.
            state_id_to_compare = header[0].replace("ï»¿", "")

            # StateID, TemporalPropertyID, Method, BinID, BinLow, BinHigh
            if len(header) == 6 and KB_HEADER_FORMAT[0] in state_id_to_compare and header[1] == KB_HEADER_FORMAT[1] \
                    and header[2] == KB_HEADER_FORMAT[3] and header[3] == KB_HEADER_FORMAT[4] \
                    and header[4] == KB_HEADER_FORMAT[5] and header[5] == KB_HEADER_FORMAT[6]:
                return True

            # StateID, TemporalPropertyID, Method, BinID, BinLow, BinHigh, BinLowScore
            if len(header) == 7 and KB_HEADER_FORMAT[0] in state_id_to_compare and header[1] == KB_HEADER_FORMAT[1] \
                    and header[2] == KB_HEADER_FORMAT[3] and header[3] == KB_HEADER_FORMAT[4] \
                    and header[4] == KB_HEADER_FORMAT[5] and header[5] == KB_HEADER_FORMAT[6] \
                    and header[6] == KB_HEADER_FORMAT[7]:
                return True

            # StateID, TemporalPropertyID, Method, BinID, BinLow, BinHigh, BinLowScore, BinLabel
            if len(header) == 8 and KB_HEADER_FORMAT[0] in state_id_to_compare and header[1] == KB_HEADER_FORMAT[1] \
                    and header[2] == KB_HEADER_FORMAT[3] and header[3] == KB_HEADER_FORMAT[4] \
                    and header[4] == KB_HEADER_FORMAT[5] and header[5] == KB_HEADER_FORMAT[6] \
                    and header[6] == KB_HEADER_FORMAT[7] and header[7] == KB_HEADER_FORMAT[8]:
                return True

            # StateID, TemporalPropertyID, TemporalPropertyName Method, BinID, BinLow, BinHigh, BinLowScore, BinLabel
            if len(header) == 9 and KB_HEADER_FORMAT[0] in state_id_to_compare and header[1] == KB_HEADER_FORMAT[1] \
                    and header[2] == KB_HEADER_FORMAT[2] and header[3] == KB_HEADER_FORMAT[3] \
                    and header[4] == KB_HEADER_FORMAT[4] and header[5] == KB_HEADER_FORMAT[5] \
                    and header[6] == KB_HEADER_FORMAT[6] and header[7] == KB_HEADER_FORMAT[7] \
                    and header[8] == KB_HEADER_FORMAT[8]:
                return True

            return False


def add_variable_names_to_vmap(kb_file_path, disc_path, vmap):
    """
    Receives a knowledge-based file with bin labels and a dictionary of a the variables and modifies the file,
    such that it contains a column with the corresponding variable names.
    :param kb_file_path: a path to the knowledge-based file
    :param disc_path: a path to the discretization folder
    :param vmap: a <string,string> dictionary that maps a variable ID to its variable name, as defined in the VMap file.
    :return:
    """
    with open(kb_file_path) as original_file:
        reader = csv.reader(original_file, delimiter=',')
        with open(os.path.join(disc_path, "states_kb_temp.csv"), 'w', newline='') as new_file:
            writer = csv.writer(new_file, delimiter=',')

            i = 0
            for row in reader:
                if i == 0:
                    row.insert(2, "TemporalPropertyName")
                    i = i + 1
                    continue
                variable_name = vmap[row[1]]
                row.insert(2, variable_name)
                writer.writerow(row)
                # modify the row to contain the new column

    # Replace the old file
    os.remove(kb_file_path)
    os.rename(os.path.join(disc_path, "states_kb_temp.csv"), kb_file_path)


def validate_kb_file_body(kb_file_path, disc_path, vmap_path):
    """
    Validates that the header of a user-submitted gradient discretization file's body
    adheres to HugoBot's standards.
    :param kb_file_path: a path to the knowledge-based file
    :param disc_path: a path to the discretization folder
    :param vmap_path: a path to the dataset's variable map file (needed for some validation paths)
    :return: True if every row:
    # Has a non-negative integer as its 1st element
    # Has a non-negative integer as its 2nd element
    # OPTIONAL has a Temporal Property Name as its 3rd element
        that fits the Name defined in the VMap for the ID in the same row
    # Has 'knowledge-based' as the 3rd element
    # Has a non-negative integer as its 4th element
    # Has a floating point number as its 5th element
    # Has a floating point number as its 6th element
    # OPTIONAL has a string describing the state as its 8th element
    False otherwise
    """
    is_labeled = False
    has_vmap_names = False
    with open(kb_file_path) as kb_file:
        reader = csv.reader(kb_file, delimiter=',')

        i = 0
        flag = True
        vmap = {}
        for row in reader:
            if i == 0:
                if row[2] == "TemporalPropertyName":
                    has_vmap_names = True
                if (len(row) == 8 and row[7] == "BinLabel") or (len(row) == 9 and row[8] == "BinLabel"):
                    is_labeled = True
                    vmap = get_variable_map(vmap_path)
                i = i + 1
                continue

            j = 0

            flag &= check_non_negative_int(row[j])
            j = j + 1
            flag &= check_non_negative_int(row[j])
            j = j + 1

            if is_labeled and has_vmap_names:
                # If the file has labels and VMap variables we have to validate the VMap variables
                flag &= (vmap[row[j - 1]] == row[j])
                j = j + 1

            flag &= (row[j] == "knowledge-based")
            j = j + 1
            flag &= check_non_negative_int(row[j])
            j = j + 1
            flag &= (check_float(row[j]) or row[j] == "#NAME?")  # workaround for -inf in excel
            j = j + 1
            flag &= check_float(row[j])
            j = j + 1

            i = i + 1
    if is_labeled and not has_vmap_names:
        # add the variable names ourselves in case there are labels but no variable names
        add_variable_names_to_vmap(kb_file_path, disc_path, vmap)
    return flag


def validate_classes_in_raw_data(raw_data_path):
    """
    Validates whether or not a given raw data file is divided into classes
    :param raw_data_path: a path to the raw data file
    :return: True if for every entity, there exists a row such that:
    # The entity ID is the first element
    # The Variable ID is -1
    # The Timestamp is 0
    # The class is a non-negative integer
    False otherwise
    """
    entity_list = get_variable_list(raw_data_path, 0)
    with open(raw_data_path) as data:
        reader = csv.reader(data, delimiter=',')
        i = 0
        for row in reader:
            if i == 0:
                i = i + 1
                continue
            entity = row[0]
            if row[1] == "-1":
                if row[2] == "0":
                    if check_non_negative_int(row[3]):
                        entity_list.remove(entity)
    return len(entity_list) == 0


def validate_file_creation(path, list_of_files):
    """
    Validates the existence of files in a certain path.
    :param path: the path that contains all of our files
    :param list_of_files: a list of files we want to make sure are in the path
    :return: True if all files exist, False otherwise
    """
    flag = True
    for file in list_of_files:
        flag &= os.path.exists(os.path.join(path, file))
    return flag


def check_if_not_int(num):
    num1 = float(num)
    if num1.is_integer() and num1 > 1:
        return False
    else:
        return True


def check_if_not_int_but_0(num):
    num1 = float(num)
    if num1.is_integer() and num1 > -1:
        return False
    else:
        return True


# </editor-fold>


# <editor-fold desc="Discretization Module">
@app.route('/addNewDisc', methods=['POST'])
@token_required
def add_new_disc(current_user):
    """
    This function handles a submission of a new discretization to the system.
    :param current_user: The user that is currently logged in.
    :param PAA
    :param NumStates - the number of states we want to send to discretization, int
    :param InterpolationGap - the interpolation gap variable we want to send to discretization , float
    :param AbMethod - the abstruct mathod we want to send to discretization, string
    :param KnowledgeBasedFile - if there is a knowledge-based file we send it as well, csv file
    :param GradientFile - if there is a gradiente file we send it as well, csv file
    :param GradientWindowSize - if there is a gradient file we send its window size, float
    :return:
    400 (BAD REQUEST) if:
    # One of the user inputs are invalid (empty/incorrect).
    # The Knowledge-based/Gradient file did not go through the validations successfully (incorrect format/not unique).
    # The user requested a TD4C discretizations and did so on a dataset with no classes.
    # The same discretization already exists in the system.

    409 (CONFLICT) if:
    # The server cannot send an email.

    500 (INTERNAL SERVER ERROR) if:
    # The discretization system has failed to create the necessary files.

    200 (OK) if all went well
    """
    # <editor-fold desc="Input tests">
    # retrieve user input from request
    data = request.form
    if not check_non_negative_int(data['PAA']) or int(data['PAA']) < 1:
        return jsonify({'message': 'Incorrect parameter: '
                                   'PAA has to be a positive integer larger than 1'}), 400

    if not check_non_negative_int(data['InterpolationGap']) or int(data['InterpolationGap']) < 1:
        return jsonify({'message': 'Incorrect parameter: '
                                   'Interpolation Gap has to be a positive integer of at least 1'}), 400

    if 'NumStates' in data.keys():
        if not check_non_negative_int(data['NumStates']) or int(data['NumStates']) < 2:
            return jsonify({'message': 'Incorrect parameter: '
                                       'Number of States has to be a positive integer of at least 2'}), 400

    if 'GradientWindowSize' in data.keys():
        if not check_non_negative_int(data['GradientWindowSize']) or int(data['GradientWindowSize']) < 2:
            return jsonify({'message': 'Incorrect parameter: '
                                       'Gradient window size has to be a positive integer of at least 2'}), 400

    if str(data['AbMethod']) == "Gradient" and 'GradientFile' not in request.files.keys():
        return jsonify({'message': 'You must provide a gradient file'}), 400

    if str(data['AbMethod']) == "Knowledge-Based" and 'KnowledgeBasedFile' not in request.files.keys():
        return jsonify({'message': 'You must provide a knowledge-based file'}), 400
    # </editor-fold>

    # <editor-fold desc="General basic setup">
    PAA = int(data['PAA'])
    AbMethod = str(data['AbMethod'])
    InterpolationGap = int(data['InterpolationGap'])
    dataset_name = str(data["datasetName"])

    # generate a unique id for our new discretization
    disc_id = str(uuid.uuid4())

    config = defaultdict(empty_string)

    dataset_path = os.path.join(DATASETS_ROOT, dataset_name)
    disc_path = os.path.join(dataset_path, disc_id)

    create_directory_disc(dataset_name, disc_id)
    dataset1 = info_about_datasets.query.filter_by(Name=dataset_name).first()
    # </editor-fold>

    # <editor-fold desc="Get variable list from VMap file">
    # retrieve temporal property id list from vmap file
    temporal_variables = []
    vmap_path = dataset_path + '/' + 'VMap.csv'
    with open(vmap_path, 'r') as vmap:
        counter = 0
        for row in vmap:
            if counter > 0:
                temporal_variables.append(row.split(',')[0])
            counter = counter + 1
    # </editor-fold>

    # <editor-fold desc="Gradient">
    # if this is a gradient discretization, validate the file first
    if 'GradientFile' in request.files.keys():
        GradientFile = request.files['GradientFile']
        gradient_window_size = data['GradientWindowSize']

        GradientFile.filename = "states_kb_gradient.csv"
        GradientFile_name = GradientFile.filename
        gradient_path = os.path.join(disc_path, secure_filename(GradientFile.filename))
        GradientFile.save(gradient_path)

        if not validate_gradient_file_header(gradient_path):
            os.remove(gradient_path)
            os.rmdir(disc_path)
            return jsonify({'message': 'the gradient file you supplied has an incorrect header.'}), 400

        if not validate_gradient_file_body(gradient_path):
            os.remove(gradient_path)
            os.rmdir(disc_path)
            return jsonify({'message': 'the gradient file you supplied has incorrect data.'}), 400

        if not validate_uniqueness(dataset_path, GradientFile_name, gradient_path):
            if check_if_already_exists(dataset1, PAA, AbMethod, 0, InterpolationGap, GradientFile_name, None):
                os.remove(gradient_path)
                os.rmdir(disc_path)
                return jsonify({'message': 'the same gradient file already exists in the system'}), 400

        config["gradient_prefix"] = " " + GRADIENT_PREFIX
        config["gradient_flag"] = " " + GRADIENT_FLAG
        config["gradient_path"] = " " + gradient_path.replace('\\', '/')
        config["gradient_window_size"] = " " + gradient_window_size
    else:
        GradientFile_name = None
        gradient_window_size = 0
    # </editor-fold>

    # <editor-fold desc="Knowledge-Based">
    # if this is a knowledge-based discretization (by value), we also need to validate the file first
    if 'KnowledgeBasedFile' in request.files.keys():
        KnowledgeBasedFile = request.files['KnowledgeBasedFile']

        KnowledgeBasedFile.filename = "states_knowledge_based.csv"
        KnowledgeBasedFile_name = KnowledgeBasedFile.filename
        kb_path = os.path.join(disc_path, secure_filename(KnowledgeBasedFile.filename))
        KnowledgeBasedFile.save(kb_path)

        if not validate_kb_file_header(kb_path):
            os.remove(kb_path)
            os.rmdir(disc_path)
            return jsonify({'message': 'the knowledge-based file you supplied has an incorrect data'}), 400

        if not validate_kb_file_body(kb_path, disc_path, vmap_path):
            os.remove(kb_path)
            os.rmdir(disc_path)
            return jsonify({'message': 'the knowledge-based file you supplied has incorrect fields.'}), 400

        if not validate_uniqueness(dataset_path, KnowledgeBasedFile_name, kb_path):
            if check_if_already_exists(dataset1, PAA, AbMethod, 0, InterpolationGap, None, KnowledgeBasedFile_name):
                os.remove(kb_path)
                os.rmdir(disc_path)
                return jsonify({'message': 'the same knowledge-based file already exists in the system'}), 400

        config["knowledge_based"] = " " + KB_PREFIX
        config["knowledge_based_path"] = " " + kb_path.replace('\\', '/')
    else:
        KnowledgeBasedFile_name = None
    # </editor-fold>

    # <editor-fold desc="Regular (including TD4C)">
    # now we need to check if we haven't seen this discretization before
    # kb excluded because we already verified the configuration's uniqueness
    # no need to make a temporal abstraction file either
    if 'GradientFile' not in request.files.keys() and 'KnowledgeBasedFile' not in request.files.keys():
        NumStates = int(data['NumStates'])
        if check_if_already_exists(dataset1, PAA, AbMethod, NumStates, InterpolationGap, GradientFile_name,
                                   KnowledgeBasedFile_name):
            return jsonify({'message': 'already exists!'}), 400

        # in case a request for a TD4C discretization came in,
        # we should verify that the raw data is divided into classes.
        # a raw data file is divided into classes if, for every entityID in the file,
        # there exists:
        # A TemporalPropertyID with the value -1,
        # A TimeStamp with the value 0,
        # And a TemporalPropertyValue of either 0 or 1. otherwise a TD4C discretization is not possible
        if "td4c" in ABSTRACTION_METHOD_CONVERSION[AbMethod]:
            if not validate_classes_in_raw_data(os.path.join(dataset_path, dataset_name + ".csv")):
                return jsonify({'message': 'TD4C requires classification labeling in the data '
                                           '(TemporalPropertyID=-1).'}), 400

    else:
        NumStates = 0
    # </editor-fold>

    # <editor-fold desc="Add to DB">
    disc = discretization(
        AbMethod=AbMethod,
        dataset=dataset1,
        GradientFile_name=GradientFile_name,
        GradientWindowSize=gradient_window_size,
        id=disc_id,
        InterpolationGap=InterpolationGap,
        KnowledgeBasedFile_name=KnowledgeBasedFile_name,
        NumStates=NumStates,
        PAA=PAA,
        Finished=False)
    db.session.add(disc)
    db.session.commit()
    # </editor-fold>

    # <editor-fold desc="Prepare query for HugoBot">
    # os.path.join() won't work here
    dataset_path = DATASETS_ROOT + '/' + dataset_name
    disc_path = DATASETS_ROOT + '/' + dataset_name + '/' + disc_id

    config["cli_path"] = " " + CLI_PATH
    config["mode"] = " " + MODE
    config["dataset_path"] = " " + dataset_path + '/' + dataset_name + ".csv"
    config["output_dir"] = " " + disc_path
    config["dataset_or_property"] = " " + DATASET_OR_PROPERTY
    config["output_dir_name"] = " " + disc_id
    config["paa_flag"] = " " + PAA_FLAG
    config["paa_value"] = " " + str(PAA)
    config["interpolation_gap"] = " " + str(InterpolationGap)

    if 'GradientFile' not in request.files.keys() and 'KnowledgeBasedFile' not in request.files.keys():
        config["discretization_flag"] = " " + DISCRETIZATION_PREFIX
        config["method"] = " " + ABSTRACTION_METHOD_CONVERSION[AbMethod]
        config["num_bins"] = " " + str(NumStates)

    run_hugobot(config)

    for filename in os.listdir(disc_path):
        if filename.endswith(".txt"):
            kl_input_path = os.path.join(disc_path, filename)
            kl_processed_input = filename.replace(".txt", "_processed.txt")
            kl_processed_input_path = os.path.join(disc_path, kl_processed_input)
            parse_kl_input(kl_input_path, kl_processed_input_path)

            os.remove(kl_input_path)
            os.rename(kl_processed_input_path, kl_input_path)
    # </editor-fold>

    # <editor-fold desc="Validate file creation and add to DB">
    mandatory_files = \
        ["entity-class-relations.csv",
         "prop-data.csv",
         "states.csv",
         "symbolic-time-series.csv",
         "KL.txt"]
    if validate_file_creation(disc_path, mandatory_files):
        disc.Finished = True
        db.session.commit()
        db.session.close()
        try:
            notify_by_email.send_an_email(
                message=f"Subject: A discretization for Your dataset \"" + dataset_name +
                        "\" has been successfully created",
                receiver_email=current_user.Email)
        except:
            return jsonify({'message': 'cannot send email!.'}), 409
        return "success!", 200
    else:
        db.session.delete(disc)
        db.session.commit()
        db.session.close()
        try:
            notify_by_email.send_an_email(
                message=f"Subject: A problem has occurred with the " +
                        "discretization you queued for Your dataset \"" + dataset_name + "\". Please try again.",
                receiver_email=current_user.Email)
        except:
            return jsonify({'message': 'cannot send email!.'}), 409
        return jsonify({'message': 'a new discretization has been requested, but a problem has occurred.'}), 500
    # </editor-fold>


def parse_kl_input(input_path, output_path):
    """
    This function performs necessary processing on the KarmaLego input
    in order for it to be understood by the KLW system.
    :param input_path: the input path to the file
    :param output_path: the path to the processed file
    :return:
    """
    index = 0
    file = open(input_path, "r+")
    t = open(output_path, "w")
    t.write(file.readline())  # startToncepts
    t.write(file.readline())  # numberOfEntities
    entity_id_line = file.readline()
    while entity_id_line:
        entity_details_line = file.readline()
        var_min, var_max = find_max_and_min(entity_details_line)
        entity_id_line = \
            entity_id_line[0:entity_id_line.index(';')] + ',' + \
            str(index) + ';' + \
            var_min + ';' + \
            var_max + '\n'
        t.write(entity_id_line)
        t.write(entity_details_line)
        entity_id_line = file.readline()
        index += 1
    file.close()


def find_max_and_min(line):
    """
    this is a helper function that finds the min and max values in an array
    :param line: in witch lins to for
    :return: the min and max values
    """
    var_min = sys.maxsize
    var_max = -sys.maxsize
    line_arr = line.split(";")
    for sec in line_arr:
        sec_arr = sec.split(",")
        if len(sec_arr) != 4:
            continue
        start_time = int(sec_arr[0])
        if start_time < var_min:
            var_min = start_time
        end_time = int(sec_arr[1])
        if end_time > var_max:
            var_max = end_time
    return str(0), str(var_max)


def run_hugobot(config):
    """
    This function receives a prepared query for hugobot, concatenates it into a CLI-ready string and runs it.
    :param config: a default dict which contains all the necessary configurations for the HugoBot system.
    :return:
    """
    # defaults for every path
    command = ""
    command += "python"  # all paths
    command += config["cli_path"]  # all paths
    command += config["mode"]  # all paths
    command += config["dataset_path"]  # all paths
    command += config["output_dir"]  # all paths
    command += config["dataset_or_property"]  # all paths
    command += config["paa_flag"]  # all paths
    command += config["paa_value"]  # all paths
    command += config["interpolation_gap"]  # all paths

    command += config["discretization_flag"]  # regular
    command += config["method"]  # regular
    command += config["num_bins"]  # regular

    command += config["gradient_prefix"]  # gradient
    command += config["gradient_flag"]  # gradient
    command += config["gradient_path"]  # gradient
    command += config["gradient_window_size"]  # gradient

    command += config["knowledge_based"]  # knowledge-based
    command += config["knowledge_based_path"]  # knowledge-based

    print(command)

    os.system(command)


@app.route('/getDISC', methods=['POST'])
@token_required
def get_disc(current_user):
    """
    This function handles a request to download a zip of all the discretization files.
    :param current_user: The user which is currently logged in.
    param: disc_id: the discretization id that we want to get data on
    :return:
    500 (INTERNAL SERVER ERROR) if:
    # The server cannot find any of the requested files

    200 (OK) if all files have been found, sends a zipped folder of all the HugoBot system's outputs.
    """
    data = request.form
    disc_id = data["disc_id"]
    disc = discretization.query.filter_by(id=disc_id).first()
    # if check_for_bad_user_disc(disc, current_user.Email):
    #     return jsonify({'message': 'dont try to fool me, you dont own it!'}), 400
    dataset = disc.dataset.Name

    disc_path = os.path.join(DATASETS_ROOT, dataset, disc_id)

    states_file_name = "states.csv"  # first try finding a regular states file

    if not os.path.exists(os.path.join(disc_path, states_file_name)):
        states_file_name = "states_kb_gradient.csv"  # try gradient
        if not os.path.exists(os.path.join(disc_path, states_file_name)):
            states_file_name = "states_kb.csv"  # try knowledge-based
            if not os.path.exists(os.path.join(disc_path, states_file_name)):
                return jsonify({'message': 'cannot find the requested states file in the server'}), 500

    disc_zip_name = "discretization.zip"

    files_to_send = [
        "entity-class-relations.csv",
        "KL.txt",
        "prop-data.csv",
        states_file_name,
        "symbolic-time-series.csv"]

    if os.path.exists(os.path.join(disc_path, "KL-class-0.0.txt")) and \
            os.path.exists(os.path.join(disc_path, "KL-class-1.0.txt")):
        files_to_send.append("KL-class-0.0.txt")
        files_to_send.append("KL-class-1.0.txt")

    create_disc_zip(disc_path, disc_zip_name, files_to_send)

    return send_file(os.path.join(disc_path, disc_zip_name))


# </editor-fold>


# <editor-fold desc="Time Intervals Mining Module">

def get_dataset_name(disc):
    """
    This function returns the dataset name for a given discretization.
    :param disc: the id of the discretization
    :return:
    the name of the dataset related to the discretization
    """
    dataset = disc.dataset
    dataset_name = dataset.Name
    return dataset_name


@app.route('/addTIM', methods=['POST'])
@token_required
def add_tim(current_user):
    """
    This function handles a new KarmaLego run attempt.
    :param current_user: The user which is currently logged in.
    param - epsilon - the value of epsilon, int
    param - max gap- int, the max_gap between the intervals for creating the index
    :param min_ver_support: float, the minimum vertical support value
    :param num_relations: int, number of relations
    :param index_same: Boolean, index same symbols or not
    :return:
    if it was a sussess run it returns status 200
    if there is already a karma lego like the user wants now it returns status 400
    """
    try:
        #makes all the validations befor making any write to the database
        data = request.form
        if check_if_not_int_but_0(data['Epsilon']):
            return jsonify({'message': 'you did not give me an integer but a float'}), 404
        if check_if_not_int(data['max Tirp Length']) or check_if_not_int(
                data['Max Gap']) or check_if_not_int(data['min_ver_support']):
            return jsonify({'message': 'you did not give me an integer but a float or a number less then 1'}), 404
        if int(data['min_ver_support']) > 100:
            return jsonify({'message': 'minimum vertical support cant be greater then 100'}), 404
        discretization_id = str(data['DiscretizationId'])
        if 'Epsilon' not in data:
            epsilon = int(0.0000)
        else:
            epsilon = int(data['Epsilon'])
        #saves all the parameters that the user passed me
        max_gap = int(data['Max Gap'])
        vertical_support = int(data['min_ver_support']) / 100
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
        email = current_user.Email
        #checking if the current discretization already exists
        if check_exists(disc, epsilon, max_gap, vertical_support, num_relations, index_same, max_tirp_length):
            return jsonify({'message': 'already exists!'}), 409
        dataset_name = get_dataset_name(disc)
        KL_id = str(uuid.uuid4())
        create_directory(dataset_name, discretization_id, KL_id)
        directory_path = dataset_name + "/" + discretization_id
        #saves the data to the dataset
        KL = karma_lego(
            discretization=disc,
            epsilon=epsilon,
            id=KL_id,
            index_same=index_same,
            max_gap=max_gap,
            max_tirp_length=max_tirp_length,
            min_ver_support=vertical_support,
            num_relations=num_relations,
            Finished=False)
        db.session.add(KL)
        db.session.commit()
        #after creating the directory, creating by karma lego 3 files: kl, kl0, kl1
        for filename in os.listdir(DATASETS_ROOT + '/' + directory_path):
            if filename.endswith(".txt"):
                start_time = time.time()
                path = DATASETS_ROOT + '/' + directory_path + '/' + filename
                out_path = DATASETS_ROOT + '/' + directory_path + '/' + KL_id + '/' + filename
                print(out_path)

                calc_offsets = True
                entity_ids_num = 2
                epsilon = epsilon
                index_same = index_same
                label = 0
                max_gap = max_gap
                max_tirp_length = max_tirp_length
                need_one_sized = True
                num_comma = 2
                num_relations = num_relations
                print_output_incrementally = True
                print_params = True
                semicolon_end = True
                skip_followers = False
                support_vec = vertical_support
                #calling the actual karma lego algorithem
                lego_0, karma_0 = RunKarmaLego.runKarmaLego(
                    calc_offsets=calc_offsets,
                    entity_ids_num=entity_ids_num,
                    epsilon=epsilon,
                    incremental_output=print_output_incrementally,
                    index_same=index_same,
                    label=label,
                    max_gap=max_gap,
                    max_tirp_length=max_tirp_length,
                    min_ver_support=support_vec,
                    need_one_sized=need_one_sized,
                    num_comma=num_comma,
                    num_relations=num_relations,
                    output_path=out_path,
                    print_params=print_params,
                    semicolon_end=semicolon_end,
                    skip_followers=skip_followers,
                    time_intervals_path=path)
            else:
                continue
        # checks if the creation of the file of the karma lego was successful and if not it deletes the record from the db
        if ((os.path.exists(DATASETS_ROOT + '/' + directory_path + '/' + KL_id + '/' + 'KL.txt'))
                or (os.path.exists(DATASETS_ROOT + '/' + directory_path + '/' + KL_id + '/' + 'KL-class-0.0.txt'))
                or (os.path.exists(DATASETS_ROOT + '/' + directory_path + '/' + KL_id + '/' + 'KL-class-1.0.txt'))):
            KL.Finished = True
            db.session.commit()
            try:
                notify_by_email.send_an_email(
                    message=f"Subject: karmalego successfully created",
                    receiver_email=email)
                db.session.close()
            except:
                return jsonify({'message': 'cannot send email!.'}), 409
            return jsonify({'message': 'karmalego created!', 'KL_id': KL_id}), 200
        else:
            db.session.delete(KL)
            db.session.commit()
            db.session.close()
            try:
                notify_by_email.send_an_email(
                    message=f"Subject: problem with creating karmalego",
                    receiver_email=email)
            except:
                return jsonify({'message': 'cannot send email!.'}), 409
            return jsonify({'message': 'did not create karmalego):'}), 409
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 404


@app.route('/getTIM', methods=['POST'])
# @token_required
def get_tim():
    """
    This function handles a download request for one of the KarmaLego output files.
    param kl_id: the id of the karma lego that in the db
    param class_num: the number of the class, could be 0,1,2
    :return: the file we asks for, like if it is kl, kl0 or kl1
    """
    try:
        data = request.form
        kl_id = data["kl_id"]
        print(kl_id)
        class_num = data["class_num"]
        KL = karma_lego.query.filter_by(id=kl_id).first()
        # if (check_for_bad_user(KL, current_user.Email)):
        #  return jsonify({'message': 'dont try to fool me, you dont own it!'}), 403
        disc = KL.discretization.id
        dataset = KL.discretization.dataset.Name
        db.session.close()
        return send_file(DATASETS_ROOT + "/" + dataset + '/' + disc + '/' + kl_id + '/' + class_num)
    except:
        db.session.close()
        return jsonify({'message': 'there is no such file to download'}), 404


# </editor-fold>


# <editor-fold desc="Upload Dataset Module">
@app.route("/stepone", methods=["POST"])
@token_required
def upload_stepone(current_user):
    """
    This function handles an upload of a new dataset.
    This is the metadata step.
    :param current_user: The user which is currently logged in.
    :param datasetName - the name of the dataset, string
    :param category - the category of the dataset, string
    :param publicPrivate - wether it public or private, string
    :param file - the dataset itself, csv
    :param description - the description of the dataset, string
    :param datasetSource - the source of the dataset, string
    :return:
    400 (BAD REQUEST) if:
    # The raw data file failed any of the validations (incorrect format/body).

    200 (OK) if all went well.
    """
    try:
        print(current_user)
        # Dataset File: user input
        raw_data_file = request.files['file']

        # Now, save the info as a tuple in the DB and the file as part of the file system:
        # info_about_datasets tuple:
        # Name (PK), Description, Public/private, Category, Size, Views, Downloads, Email

        # Name: user input
        dataset_name = request.form['datasetName']

        # Description: user input
        description = request.form['description']

        # Public/private: user input
        public_private = request.form['publicPrivate']

        # Category: user input
        category = request.form['category']

        # source: user input
        dataset_source = request.form['datasetSource']

        # Views: generated (instantiated to 0)
        # views = "0"

        # Downloads: generated (instantiated to 0)
        # downloads = "0"

        # Email: user input (identifier of the user)
        # email = "3"

        # Validate dataset file integrity
        # correct format for raw data file:
        # EntityID	TemporalPropertyID	TimeStamp	TemporalPropertyValue

        # Save the dataset file. in case it does not meet the requirements, delete it.

        print(dataset_name)
        create_directory_for_dataset(dataset_name)

        print(raw_data_file.filename)

        raw_data_file.filename = dataset_name + '.csv'

        raw_data_path = os.path.join(DATASETS_ROOT, dataset_name, secure_filename(raw_data_file.filename))

        raw_data_file.save(raw_data_path)

        # Size: generated (calculated from file)
        size = os.path.getsize(raw_data_path)
        size = round(size / 1000000, 2)  # B -> MB

        if not validate_raw_data_header(raw_data_path):
            os.remove(raw_data_path)
            os.rmdir(os.path.join(DATASETS_ROOT, dataset_name))
            return jsonify({'message': 'Either your Dataset\'s header is not in the correct format, '
                                       'or you have more than ' +
                                       str(len(RAW_DATA_HEADER_FORMAT)) +
                                       ' columns in your data'}), 400

        if not validate_raw_data_body(raw_data_path):
            os.remove(raw_data_path)
            os.rmdir(os.path.join(DATASETS_ROOT, dataset_name))
            return jsonify({'message': 'at least one row is not in the correct format'}), 400

        exists = info_about_datasets.query.filter_by(Name=dataset_name).first()

        if exists is None:
            exists = None
        else:
            return jsonify({'message': 'dataset with that name already been created'}), 400

        dataset1 = info_about_datasets(Name=dataset_name, Description=description, source=dataset_source,
                                       public_private=public_private, category=category, size=size, views=0,
                                       downloads=0, owner=current_user)
        db.session.add(dataset1)
        db.session.commit()

        # db.session.rollback()
        # db.session.close()
        # return jsonify({'message': 'problem with data'}), 400
        db.session.close()
        return jsonify({'message': 'Dataset Successfully Validated!'})
    except:
        return jsonify({'message': 'one of the arguments is missing'}),400


@app.route("/steptwo", methods=["POST"])
@token_required
def upload_steptwo(current_user):
    """
    This function handles an upload of a new dataset.
    This is the variable map step, where a user submits a custom variable map file.
    :param current_user: The user which is currently logged in.
    :param csv - the csv file that we want to send to the server
    :param datasetName - the name of the dataset to atach the vmap to
    :return:
    400 (BAD REQUEST) if:
    # The submitted variable map file failed any of the validations
    (incorrect header, not all variable IDs are in the file).
    # There was an unexpected problem in the server.

    200 (OK) if all went well.
    """
    try:
        file = request.files['file']
        print(file)
        dataset_name = request.form['datasetName']
        print(dataset_name)
        dataset_path = os.path.join(DATASETS_ROOT, dataset_name)
        raw_data_path = os.path.join(dataset_path, dataset_name + '.csv')
        file.filename = "VMap.csv"
        vmap_path = os.path.join(dataset_path, secure_filename(file.filename))
        file.save(vmap_path)

        if not validate_vmap_header(vmap_path):
            os.remove(vmap_path)
            return jsonify({'message': 'Either your VMap File\'s header is not in the correct format, '
                                       'or you have more than ' +
                                       str(len(VMAP_HEADER_FORMAT)) +
                                       ' columns in your data'}), 400

        if not validate_id_integrity(raw_data_path, vmap_path):
            os.remove(vmap_path)
            return jsonify({'message': 'The list of variables you provided does not match the raw data file. '
                                       'Please make sure you are mapping each and every variable id in your data,'
                                       'and only the ones in your data.'}), 400

    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'VMap Registered Successfully!'})


@app.route("/getVariableList", methods=["GET"])
def get_variable_list_request():
    """
    This function handles a request for a dataset's variable list
    param dataset_id: the id of the dataset
    :return: A list of all the variables in a certain dataset
    """
    try:
        dataset_name = request.args.get("dataset_id")
        print(dataset_name)
        dataset_path = os.path.join(DATASETS_ROOT, dataset_name, dataset_name + '.csv')
        column_in_data = 1
        list_to_return = get_variable_list(dataset_path, column_in_data)
        list_to_return = [int(x) for x in list_to_return]
        list_to_return = sorted(list_to_return)
        return jsonify({'VMapList': list_to_return})
    except IOError:
        return jsonify({'message': 'a variable list for an unknown dataset has been received.'
                                   ' please check your request and try again.'}), 400


@app.route("/steptwocreate", methods=['POST'])
@token_required
def step_two_create(current_user):
    """
    This function handles an upload of a new dataset.
    This is the variable map step, where a user submits a variable map file he made with the HugoBot UI.
    :param current_user: The user which is currently logged in.
    :param csv - the csv file that we want to send to the server
    :param datasetName - the name of the dataset to atach the vmap to
    :return:
    400 (BAD REQUEST) if:
    # The submitted variable map file failed any of the validations (empty fields, duplicate variable names).
    # There was an unexpected problem in the server.

    200 (OK) if all went well.
    """
    try:
        file = request.form['csv']

        file = file.split('\n')

        for i in range(len(file)):
            file[i] = file[i].split(',')
            if len(file[i]) != 3 or file[i][0] == "" or file[i][1] == "" or file[i][2] == "":
                return jsonify({'message': 'please verify all variable names and/or descriptions are not empty'}), 400

        # no need to check ids
        variable_names = [row[1] for row in file]
        if len(variable_names) != len(set(variable_names)):
            return jsonify({'message': 'please verify there are no duplicate variable names'}), 400

        print(file)
        dataset_name = request.form['datasetName']
        print(dataset_name)

        dataset_path = DATASETS_ROOT + '/' + dataset_name
        vmap_path = dataset_path + '/' + 'VMap.csv'

        with open(vmap_path, 'w', newline='') as vmap:
            writer = csv.writer(vmap, delimiter=',')
            writer.writerow(['Variable ID', 'Variable Name', 'Description'])
            for row in islice(file, 0, None):
                writer.writerow([row[0], row[1], row[2]])

    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'VMap Registered Successfully!'})


@app.route("/stepthree", methods=["POST"])
@token_required
def upload_stepthree(current_user):
    """
    This function handles an upload of a new dataset.
    This is the entity file step, where a user chooses to submit a custom entity file.
    :param current_user: The user which is currently logged in.
    :param file - the entities file, csv
    :param datasetName - the name of the dataset that the entities file belongs to
    :return:
    400 (BAD REQUEST) if:
    # The submitted entity file failed any of the validations
    (leftmost column is not 'id', not all entity IDs are in the data).
    # There was an unexpected problem in the server.

    200 (OK) if all went well.
    """
    try:
        if 'file' in request.files:
            file = request.files['file']
            print(file)
            dataset_name = request.form['datasetName']
            print(dataset_name)

            dataset_path = os.path.join(DATASETS_ROOT, dataset_name)
            raw_data_path = os.path.join(dataset_path, dataset_name + '.csv')
            file.filename = "Entities.csv"
            entity_path = os.path.join(DATASETS_ROOT, dataset_name, secure_filename(file.filename))

            file.save(entity_path)

            with open(entity_path) as entities:
                reader = csv.reader(entities, delimiter=',')
                for header in islice(reader, 0, 1):

                    # solves a utf-8-bom encoding issue where ï»¿ gets added in the beginning of .csv files.
                    entity_id_to_compare = header[0].replace("ï»¿", "")

                    if entity_id_to_compare != "id":
                        # if "id" not in entity_id_to_compare:
                        entities.close()
                        os.remove(entity_path)
                        return jsonify({'message': 'leftmost column of entities file must be \"id\"'}), 400

            if not validate_entity_id_integrity(raw_data_path, entity_path):
                os.remove(entity_path)
                return jsonify({'message': 'The list of entities you provided does not match the raw data file. '
                                           'Please make sure you are mapping each and every entity id in your data,'
                                           'and only the ones in your data.'}), 400
    except:
        db.session.rollback()
        db.session.close()
        return jsonify({'message': 'problem with data'}), 400
    db.session.close()
    return jsonify({'message': 'Dataset Uploaded successfully!'}), 200


# </editor-fold>


# <editor-fold desc="Visualization Files">
@app.route("/checkIfVisualPossible", methods=["GET"])
def check_if_visual_possible():
    dataset_name = request.args.get("dataset_name")
    disc_name = request.args.get("disc_name")
    kl_name = request.args.get("kl_name")
    kl_path = os.path.join(DATASETS_ROOT, dataset_name, disc_name, kl_name)
    try:
        kl_no_classes = os.path.join(kl_path, "KL.txt")
        with open(kl_no_classes) as kl:
            header = kl.readline()
            second_line = kl.readline()
            if second_line == "":
                return jsonify({'message': 'Cannot perform Visualization '
                                           'as one or more of the KarmaLego outputs contain no TIRPs.'}), 500
            else:
                return "OK", 200
    except FileNotFoundError:
        try:
            kl_class_1 = os.path.join(kl_path, "KL-class-1.0.txt")
            with open(kl_class_1) as kl_1:
                header = kl_1.readline()
                second_line_1 = kl_1.readline()
                if second_line_1 == "":
                    return jsonify({'message': 'Cannot perform Visualization '
                                               'as one or more of the KarmaLego outputs contain no TIRPs.'}), 500

            kl_class_0 = os.path.join(kl_path, "KL-class-0.0.txt")
            with open(kl_class_0) as kl_0:
                header = kl_0.readline()
                second_line_0 = kl_0.readline()
                if second_line_0 == "":
                    return jsonify({'message': 'Cannot perform Visualization '
                                               'as one or more of the KarmaLego outputs contain no TIRPs.'}), 500
            return "OK", 200
        except FileNotFoundError:
            return jsonify({'message': 'could not find the KarmaLego outputs'}), 400


@app.route("/getRawDataFile", methods=["GET"])
def get_raw_data_file():
    """
    :return: Returns a raw data file with the requested dataset id
    """
    dataset_name = request.args.get("id")
    print(dataset_name)
    return send_file(DATASETS_ROOT + '/' + dataset_name + '/' + dataset_name + '.csv'), 200


@app.route("/getEntitiesFile", methods=["GET"])
def get_entities_file():
    """
    :return:
    404 (NOT FOUND) if:
    # The entity file cannot be found.

    200 (OK) if the file exists, Returns an entity file with the requested dataset id
    """
    try:
        dataset_name = request.args.get("id")
        print(dataset_name)
        return send_file(DATASETS_ROOT + '/' + dataset_name + '/' + 'Entities.csv'), 200
    except FileNotFoundError:
        return jsonify({'message': 'the request Entities file cannot be found.'}), 404


@app.route("/getStatesFile", methods=["GET"])
def get_states_file():
    """
    param dataset_id: the id of the dataset, string
    param disc_id: the id of the discretization, string
    :return:
    404 (NOT FOUND) if:
    # The states file cannot be found.

    200 (OK) if the file exists, Returns a states file with the requested dataset id and disc id
    """
    try:
        dataset_name = request.args.get("dataset_id")
        print(dataset_name)
        disc_name = request.args.get("disc_id")
        print(disc_name)
        return send_file(DATASETS_ROOT + '/' + dataset_name + '/' + disc_name + '/' + 'states.csv'), 200
    except FileNotFoundError:
        return jsonify({'message': 'the request States file cannot be found.'}), 404


@app.route("/getKLOutput", methods=["GET"])
def get_kl_file():
    try:
        """
        param dataset_id: the id of the dataset
        param disc_id: the id of the discretization
        param kl_id: the id of the karmalego output
        :return:
        404 (NOT FOUND) if:
        # No KL output file can be found.

        200 (OK) if the file can be found, sends a KL output file. 
        If the 'class' argument is present in the URL, sends the KL output file of the requested class.
        """
        dataset_name = request.args.get("dataset_id")
        print(dataset_name)
        disc_name = request.args.get("disc_id")
        print(disc_name)
        kl_name = request.args.get("kl_id")
        print(kl_name)
        if "class" in request.args.keys():
            kl_class = request.args.get("class")
            return send_file(DATASETS_ROOT + '/' +
                             dataset_name + '/' +
                             disc_name + '/' +
                             kl_name + '/' +
                             'KL-class-' + kl_class + '.0.txt'), 200
        return send_file(DATASETS_ROOT + '/' +
                         dataset_name + '/' +
                         disc_name + '/' +
                         kl_name + '/KL.txt'), 200
    except FileNotFoundError:
        return jsonify({'message': 'the request KarmaLego output file cannot be found.'}), 404


# </editor-fold>


@app.route("/incrementViews", methods=["POST"])
def increment_views():
    """
    Increases the view count of a dataset by 1.
    :param datset_id: the id of the dataset we want to increament his views, int
    :return: the new number of views in the database
    """
    dataset_name = request.args.get('dataset_id')
    dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
    views = dataset.views + 1
    dataset.views = views
    db.session.commit()
    db.session.close()
    return jsonify({'message': 'success', 'views': views}), 200


@app.route("/incrementDownload", methods=["POST"])
def increment_download():
    """
    Increases the download count of a dataset by 1.
    :param datset_id: the id of the dataset we want to increament his downloads
    :return: the new number of downloads in the database
    """
    dataset_name = request.args.get('dataset_id')
    dataset = info_about_datasets.query.filter_by(Name=dataset_name).first()
    download = dataset.downloads + 1
    dataset.downloads = download
    db.session.commit()
    db.session.close()
    return jsonify({'message': 'success', 'downloads': download}), 200


@app.route('/getUserName', methods=['GET'])
@token_required
def get_user_name(current_user):
    """
    Returns the current user's username.
    :param current_user: The user which is currently logged in.
    :return:
    403 (FORBIDDEN) if:
    # The current user cannot get the information.

    200 (OK) if the user has permissions, returns the first name and last name of the user.
    """
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
    """
    Returns the current user's email address.
    :param current_user: The user which is currently logged in.
    :return:
    403 (FORBIDDEN) if:
    # The current user cannot get the information.

    200 (OK) if the user has permissions, returns the email of the user.
    """
    try:
        email = current_user.Email
        print("get email request, email=" + email)
        db.session.close()
        return jsonify({'Email': email})
    except:
        db.session.close()
        return jsonify({'message': 'problem with data'}), 403


# sends all the info about the data sets
@app.route('/getAllDataSets', methods=['GET'])
def get_all_datasets():
    """
    Returns info on all datasets in the server.
    :return:
    500 (INTERNAL SERVER ERROR) if:
    # There has been an unexpected server error.

    200 (OK) if all went well, the response contains:
    # lengthNum: The number of datasets
    # A table that contains metadata about each dataset in the system.
    """
    try:
        datasets = info_about_datasets.query.all()
        to_return = {}
        x = 0
        to_return["lengthNum"] = len(datasets)
        for curr_dataset in datasets:
            full_name = curr_dataset.owner.FName + " " + curr_dataset.owner.LName
            to_return[str(x)] = {
                "Category": curr_dataset.category,
                "DatasetName": curr_dataset.Name,
                "Owner": full_name,
                "PublicPrivate": curr_dataset.public_private,
                "Size": str(curr_dataset.size)}
            x = x + 1
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an error!'}), 500


@app.route("/getInfo", methods=["GET"])
def get_all_info_on_dataset():
    """
    param id: the name of the dataset
    Returns all the information on a requested dataset.
    :return: A JSON object with the info about a dataset.
    """
    dataset_name = request.args.get("id")
    info = info_about_datasets.query.filter_by(Name=dataset_name).first()
    print(info.Name)
    return jsonify(
        {"category": info.category,
         "Description": info.Description,
         "downloads": info.downloads,
         "Name": info.Name,
         "owner_name": info.Email,
         "size": str(info.size) + " MB",
         "source": info.source,
         "views": info.views}), 200


@app.route('/getDataOnDataset', methods=['GET'])
@token_required
def get_data_on_dataset(current_user):
    """
    This function returns all of the existing discretization and KL runs for a given dataset.
    :param current_user: The user which is currently logged in.
    param id: the name of the dataset
    :return:the data on a spesific dataset
    """
    try:
        dataset_name = request.args.get("id")
        print(current_user)
        if check_for_authorization(current_user, dataset_name):
            return jsonify({'message': 'dont try to fool me, you dont own it!'}), 403
        discretizations = discretization.query.filter_by(dataset_Name=dataset_name, Finished=True).all()
        disc_to_return = {}
        x = 0
        num = 0
        disc_to_return["lengthNum"] = len(discretizations)
        karma_arr = []
        for curr_disc in discretizations:
            karma_arr.append(karma_lego.query.filter_by(discretization=curr_disc, Finished=True).all())
            num = num + len(karma_arr[x])
            disc_to_return[str(x)] = {
                "BinsNumber": str(curr_disc.NumStates),
                "id": str(curr_disc.id),
                "InterpolationGap": str(curr_disc.InterpolationGap),
                "MethodOfDiscretization": str(curr_disc.AbMethod),
                "PAAWindowSize": str(curr_disc.PAA)}
            x = x + 1
        x = 0
        karma_to_return = {"lengthNum": num}

        for karma in karma_arr:
            for curr_karma in karma:
                if curr_karma.index_same:
                    i_s = "true"
                else:
                    i_s = "false"
                karma_to_return[str(x)] = {
                    "BinsNumber": str(curr_karma.discretization.NumStates),
                    "discId": curr_karma.discretization.id,
                    "epsilon": str(curr_karma.epsilon),
                    "indexSame": i_s,
                    "InterpolationGap": str(curr_karma.discretization.InterpolationGap),
                    "karma_id": str(curr_karma.id),
                    "MaxGap": str(curr_karma.max_gap),
                    "maxTirpLength": str(curr_karma.max_tirp_length),
                    "MethodOfDiscretization": str(curr_karma.discretization.AbMethod),
                    "numRelations": str(curr_karma.num_relations),
                    "PAAWindowSize": str(curr_karma.discretization.PAA),
                    "VerticalSupport": str(curr_karma.min_ver_support)}
                x = x + 1
        to_return = {"disc": disc_to_return, "karma": karma_to_return}
        db.session.close()
        return jsonify(to_return)
    except:
        db.session.close()
        return jsonify({'message': 'there has been an eror!'}), 500


@app.route('/getDatasetFiles', methods=['GET'])
@token_required
def get_dataset_files(current_user):
    """
    This function handles a download request for a dataset's files.
    :param current_user: The user which is currently logged in.
    param dataset_id: the name of the dataset
    :return:
    500 (INTERNAL SERVER ERROR) if:
    # Any of the requested files could not be found in the server.

    200 (OK) if all files exist, returns a zipped folder of all the dataset files.
    """
    dataset_name = request.args.get('dataset_id')

    dataset_path = os.path.join(DATASETS_ROOT, dataset_name)

    if os.path.exists(dataset_path):
        files_to_send = [dataset_name + ".csv", "VMap.csv"]
        if os.path.exists(os.path.join(dataset_path, "Entities.csv")):
            files_to_send.append("Entities.csv")
    else:
        return jsonify({'message': 'cannot find the requested data file in the server'}), 500

    data_zip_name = dataset_name + ".zip"

    create_disc_zip(dataset_path, data_zip_name, files_to_send)

    return send_file(os.path.join(dataset_path, data_zip_name))


@app.route("/getVMapFile", methods=["GET"])
def get_vmap_file():
    """
    Returns the variable map file of a requested dataset.
    param id: the name of the dataset
    :return:
    404 (NOT FOUND) if:
    # The requested file cannot be found in the server.

    200 (OK) if the file exists, returns the variable map file
    """
    try:
        dataset_name = request.args.get("id")
        print(dataset_name)
        return send_file(DATASETS_ROOT + '/' + dataset_name + '/' + 'VMap.csv'), 200
    except FileNotFoundError:
        return jsonify({'message': 'the request VMap file cannot be found.'}), 404


@app.route("/getExampleFile", methods=["GET"])
def get_example_file():
    """
    Returns a requested example file for what an acceptable user-submitted file should look like.
    param file: the csv file
    :return:
    404 (NOT FOUND) if:
    # The requested file cannot be found in the server.

    200 (OK) if the file exists, returns the requested example file
    """
    try:
        file_name = request.args.get("file")
        print(file_name)
        file_path = os.path.join(SERVER_ROOT, "Resources", file_name + '.csv')
        print(file_path)
        return send_file(file_path), 200
    except FileNotFoundError:
        return jsonify({'message': 'the request file cannot be found.'}), 404


@app.route("/razTest", methods=["GET"])
def raz_test():
    return "hello"

"""
ower application runs on port 8080 but to the outside world it looks like port 80
"""
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, threaded=True)
