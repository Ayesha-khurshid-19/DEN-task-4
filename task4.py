from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        if User.query.filter_by(username=username).first():
            return jsonify(message="User already exists"), 409

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify(message="User registered successfully",user_id=new_user.id)

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.username)
            return jsonify(access_token=access_token)

        return jsonify(message="Invalid credentials"), 401

class UserCRUD(Resource):
    @jwt_required()
    def get(self, user_id):
        user = User.query.get(user_id)
        if user:
            return jsonify(id=user.id, username=user.username)
        return jsonify(message="User not found"), 404

    @jwt_required()
    def put(self, user_id):
        data = request.get_json()
        user = User.query.get(user_id)
        if user:
            user.username = data['username']
            user.password = generate_password_hash(data['password'])
            db.session.commit()
            return jsonify(message="User updated successfully")
        return jsonify(message="User not found"), 404

    @jwt_required()
    def delete(self, user_id):
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify(message="User deleted successfully")
        return jsonify(message="User not found"), 404

@app.route('/')
def home():
    return "Welcome to the Flask API!"

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserCRUD, '/user/<int:user_id>')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)

