"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS

""" JWT Modules """
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

""" API modules """
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
#from models import Person

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)


# Login
@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    if "email" not in body  or body['email'] == "":
        raise APIException("User not found", status_code=400)
    if "password" not in body  or body['password'] == "":
        raise APIException("User not found", status_code=400)
    
    user = User.query.filter_by(email=body['email']).first()

    if user == None:
        raise APIException("User not found", status_code=404)
    if body['email'] != user.email:
        raise APIException("User not found", status_code=400)
    else:
        access_token = create_access_token(identity=body['email'])
        return jsonify(access_token=access_token)


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


######  All user endpoints ######
@app.route('/user', methods=['GET'])
def handle_users():

    users = User.query.all()
    users_list = list(map(lambda user: user.serialize(), users))

    return jsonify(users_list), 200


@app.route('/user/<int:user_id>', methods=['GET'])
def handle__one_user(user_id):

    user = User.query.get(user_id)
    if user == None:
         raise APIException("User not found", status_code=400)
    

    return jsonify(user.serialize()), 200


@app.route('/user', methods=['POST'])
def handle_add_user():

    # First we get the payload json
    body = request.get_json()

    if body is None:
        raise APIException("You need to specify the request body as a json object", status_code=400)
    if 'password' not in body:
        raise APIException('You need to specify the password', status_code=400)
    if 'email' not in body:
        raise APIException('You need to specify the email', status_code=400)
    if 'is_active' not in body:
        raise APIException('You need to specify the is_active', status_code=400)

    # at this point, all data has been validated, we can proceed to inster into the bd
    new_user = User(password=body['password'], email=body['email'], is_active=body['is_active'])
    db.session.add(new_user)
    db.session.commit()
    return f"User {body['email']} was successfully added", 200


@app.route('/user/<int:user_id>', methods=['PUT'])
def handle_update_user(user_id):

    # First we get the payload json
    body = request.get_json()
    user = User.query.get(user_id)
    if user is None:
        raise APIException('User not found', status_code=404)

    if "password" in body:
        user.password = body["password"]
    if "email" in body:
        user.email = body["email"]
    
    db.session.commit()

    return f"User was successfully updated", 200

@app.route('/user/<int:user_id>', methods=['DELETE'])
def handle_delete_user(user_id):

    user = User.query.get(user_id)
    if user is None:
        raise APIException('User not found', status_code=404)
    db.session.delete(user)
    db.session.commit()
    return f"User was deleted successfully", 200


# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
