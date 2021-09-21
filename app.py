import os
import re
import datetime
import jwt as jwt1
from models import *
import geopy.distance 
from apispec import APISpec
from functools import wraps
from flasgger import Swagger
from sqlalchemy.sql import func
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:admin@localhost:5432/test_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'

db = SQLAlchemy(app)

# # for swagger documentation
swagger = Swagger(app)
#http://localhost:5000/apidocs/




# JWT Required Decorator
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']

       if not token:
           return jsonify({'message': 'a valid token is missing'}), 401
       try:
           data = jwt1.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
           current_user = Users.query.filter_by(id=data['id']).first()
       except:
           return jsonify({'message': 'Token is INVALID or EXPIRED'}), 405
       return f(current_user, *args, **kwargs)
   return decorator



# Validations Check
def validationsCheck(username,email,password):

    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    usernameCheck = Users.query.filter_by(userName=username).first()
    emailCheck = Users.query.filter_by(email=email).first()

    if usernameCheck:
        return "Username Already Taken by another user"

    if emailCheck:
        return "Email Already Taken by another user"

    if(re.fullmatch(regex, email)):
        pass
    else:
        return "Invalid Email"

    if len(password) < 10:
        return "Password must be atleast of 10 Characters"



#Create new User Endpoint
@app.route('/signUp', methods=['POST'])
def signUp():
    """
    Create New User.
    ---
    description: Create New User.
    parameters:
        - 
          in: body
          name: body
          required: true
          schema:
            id : user
            required:
              - fName
              - lName
              - userName
              - email
              - password
            properties:
              fName:
                type: string
              lName:
                type: string
              userName:
                type: string
              email:
                type: string
              password:
                type: string
    responses:
      200:
        description: User Created Successfully.
      401:
        description: Something Wrong.
    """
    
    data = request.get_json()
    
    msg = validationsCheck(data['userName'], data['email'], data['password'])
    
    if msg:
        return jsonify({"Error Message":msg}),401
    
    hashedPassword = generate_password_hash(data['password'], method = 'sha256')

    newUser = Users(fName = data['fName'], lName = data['lName'], email = data['email'], userName = data['userName'], 
    password = hashedPassword)

    db.session.add(newUser)
    db.session.commit()

    return jsonify({'message':'New User Created'}), 200



#for jwt authentication
@app.route('/signIn', methods=['POST'])
def signIn():
    """
    User SignIn.
    ---
    description: User SigIn.
    components:
        securitySchemes:
            BasicAuth:
              type: basic
    security:
        - 
          basicAuth: []
    parameters:
        - 
          in: header
          name: Authorization
          type: string
          required: true
    responses:
      200:
        description: User Created Successfully.
      401:
        description: Something Wrong.
    """

    print("Wellcome")
    auth = request.authorization #Basic Auth

    if not auth or not auth.username or not auth.password: 
        return jsonify('could not verify', 401, {'Authentication': 'login required"'})   

    # Querying in the User table
    user = Users.query.filter_by(userName=auth.username).first()

    if not user:
        return jsonify({'message':'Login Unsuccessfull'}), 401

    if check_password_hash(user.password, auth.password):
        #Creating the access token
        access_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
        #Creating the refresh token
        refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, app.config['JWT_SECRET_KEY'], "HS384")
        #Setting access token in response
        resp = jsonify({'x-access-tokens': access_token})
        #Setting Refresh token in ccokies as httponly
        resp.set_cookie('refresh_token', refresh_token, httponly = True)

        return resp, 200

    return jsonify({'message':'Login Unsuccessfull'}), 401




# Refresh the access token
@app.route('/refresh', methods=['POST'])
def refresh():
    """
    Refresh Token.
    ---
    description: Refresh Token.
    parameters:
        - 
          name: refresh_token
          in: cookies
          type: string
          required: true
        
    responses:
      200:
        description: Jobs of List.
      404:
        description: No Jobs found.
    """
    #Getting refresh token from cookies
    refresh = request.cookies.get('refresh_token')
    try:
        #Decoding The refresh token for authentication
        decoded = jwt1.decode(refresh, app.config['JWT_SECRET_KEY'], algorithms=["HS384"])
        # Searching if the user id of jwt exists in our DB
        user = Users.query.filter(decoded['id'] == Users.id).first()
        if user:
            # Creating new access and refresh tokens
            access_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
            refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(weeks=1)}, app.config['JWT_SECRET_KEY'], "HS384")
            resp = jsonify({'x-access-tokens': access_token})
            resp.set_cookie('refresh_token', refresh_token, httponly = True)
            return resp, 200
    except:

        return jsonify({'msg':'Unauthorized Access'}), 401
    return jsonify({'msg': "Refresh cookies not valid"})



def serialize_data(data):
      job_data = {}
      job_data['id'] = data.id
      job_data['user_id'] = data.user_id
      job_data['jobTitle'] = data.jobTitle
      job_data['jobDesc'] = data.jobDesc
      job_data['jobRate'] = data.jobRate
      job_data['latitiude'] = data.latitiude
      job_data['longitude'] = data.longitude
      job_data['isActive'] = data.isActive
      job_data['jobCreated'] = data.jobCreated
      job_data['jobUpdated'] = data.jobUpdated
      return job_data

#Jobs API CRUD Operation


#Jobs GET All jobs with kilometer filtration  using lat and long Endpoint
@app.route('/jobs', methods=['GET'])
@token_required
def get_all_job(current_user):
    """
    All Jobs.
    ---
    description: List of Jobs.
    parameters:
        - 
          name: x-access-tokens
          in: header
          type: string
          required: true
        - 
          in: query
          name: id
          description: Filter by id.
          required: false
          schema:
            type: string
        - 
          in: query
          name: kilometer
          required: false
          schema:
            type: string
        - 
          in: query
          name: lat
          required: false
          schema:
            type: string
        - 
          in: query
          name: longi
          required: false
          schema:
            type: string
    responses:
      200:
        description: Jobs of List.
      404:
        description: No Jobs found.
    """

    lat = request.args.get('lat', type=float , default=None)
    longi = request.args.get('longi', type=float , default=None)
    kilometer = request.args.get('kilometer', type=int , default=None)
    id = request.args.get('id', type=int , default=None)

    alldata = Jobs.query.all()

    if not alldata:
        return jsonify({'message':'No Jobs found'}), 404
    
    output = []
    if id:
      data = Jobs.query.filter_by(id=id).first()
      if not data:
        return jsonify({'message':'No Job found'}), 404
      else:
        job_data = serialize_data(data)
        output.append(job_data)

    elif kilometer and lat and longi:
        for data in alldata:    
            coords_1 = (float(data.latitiude), float(data.longitude))
            coords_2 = (lat, longi)
            distance = geopy.distance.geodesic(coords_1, coords_2).km
            if distance <= kilometer:

                job_data = serialize_data(data)
                output.append(job_data)
        if output == []:
          return jsonify({'message':'No Job found'}), 404

    else:
        for data in alldata:
            job_data = serialize_data(data)
            output.append(job_data)

    return jsonify({'data':output}), 200


#Create new job Endpoint
@app.route('/jobs', methods=['POST'])
@token_required
def add_job(current_user):
    """
    Add Job.
    ---
    description: Add New Job.
    parameters:
        - 
          name: x-access-tokens
          in: header
          type: string
          required: true
        - 
          in: body
          name: body
          required: true
          schema:
            id : job
            required:
              - jobTitle
              - jobDesc
              - jobRate
              - latitiude
              - longitude
            properties:
              jobTitle:
                type: string
              jobDesc:
                type: string
              jobRate:
                type: string
              latitiude:
                type: string
              longitude:
                type: string
    responses:
      200:
        description: Job Added Successfully.
      404:
        description: Something is Wrong.
    """

    data = request.get_json()

    new_job = Jobs(user_id = current_user.id, jobTitle = data['jobTitle'], jobDesc = data['jobDesc'], jobRate = data['jobRate'], 
    latitiude = data['latitiude'], longitude = data['longitude'])

    db.session.add(new_job)
    db.session.commit()
    
    return jsonify({'message':'New Job Created'}), 200


#Edit job(by id) Endpoint
@app.route("/jobs/<id>", methods=['PUT'])
@token_required
def edit_job(current_user, id):
    """
    Update Job.
    ---
    description: Update Job by ID.
    parameters:
        - 
          name: x-access-tokens
          in: header
          type: string
          required: true
        - 
          in: path
          name: id
          type: string
          required: true
        - 
          in: body
          name: body
          required: true
          schema:
            id : job
            required:
              - jobTitle
              - jobDesc
              - jobRate
              - latitiude
              - longitude
            properties:
              jobTitle:
                type: string
              jobDesc:
                type: string
              jobRate:
                type: string
              latitiude:
                type: string
              longitude:
                type: string
    responses:
      200:
        description: Job Added Successfully.
      404:
        description: Something is Wrong.
    """

    data = request.get_json()

    value = Jobs.query.filter_by(id=id).first()

    if not value:
        return jsonify({'message':'No Job found'}), 404

    value.update_to_db(data)

    return jsonify({'message':'Job Information Updated'}), 200


#Soft delete a job(by id) Endpoint
@app.route("/jobs/<id>", methods=['DELETE'])
@token_required
def del_job(current_user, id):
    """
    Soft Delete Job.
    ---
    description: Delete Job by ID.
    parameters:
        - 
          name: x-access-tokens
          in: header
          type: string
          required: true
        - 
          in: path
          name: id
          type: string
          required: true
    responses:
      200:
        description: Job Deleted by is_active flag.
      404:
        description: No Jobs found.
    """
    job = Jobs.query.filter_by(id=id).first()

    if not job:
        return jsonify({'message':'No job found'}), 404
    
    job.isActive = False

    db.session.commit()
    return jsonify({'message':'Job Deleted Successfully'}), 200


#Hard delete a job(by id) Endpoint
@app.route("/jobs/del/<id>", methods=['DELETE'])
@token_required
def del_job_hard(current_user, id):
    """
    Hard Delete Job.
    ---
    description: Delete Job by ID.
    parameters:
        - 
          name: x-access-tokens
          in: header
          type: string
          required: true
        - 
          in: path
          name: id
          type: string
          required: true
    responses:
      200:
        description: Job Deleted from Database.
      404:
        description: No Jobs found.
    """
    job = Jobs.query.filter_by(id=id).first()

    if not job:
        return jsonify({'message':'No job found'}), 404
    
    db.session.delete(job)
    db.session.commit()
    return jsonify({'message':'Job Deleted Successfully'}), 200


if __name__ == '__main__':        
    app.run(debug=True)