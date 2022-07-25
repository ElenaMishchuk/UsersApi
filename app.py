from flask import Flask, request
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://sql11508449:6rNYsa3SYd@sql11.freemysqlhosting.net/sql11508449"

table_query = """
CREATE TABLE IF NOT EXISTS users (
id INTEGER AUTO_INCREMENT PRIMARY KEY,
email VARCHAR(100),
password VARCHAR(300)
);
"""

class Register(Resource):
    def post(self):
        data = request.json
        if "email" not in data or len(data["email"]) == 0:
            return {"message": "Email is required"}, 400
        if "password" not in data or len(data["password"]) == 0:
            return {"message": "Password is required"}, 400
        password_hash = generate_password_hash(data["password"], method="sha256")
        email = data["email"]
        db.engine.execute(f"INSERT INTO users(email, password) VALUES('{email}', '{password_hash}')")
        return {"message": "success"}, 201


class Login(Resource):
    def post(self):
        data = request.json
        if "email" not in data or len(data["email"]) == 0:
            return {"message": "Email is required"}, 400
        if "password" not in data or len(data["password"]) == 0:
            return {"message": "Password is required"}, 400
        email = data["email"]
        result = db.engine.execute(f"SELECT * FROM users WHERE email='{email}'")
        for row in result:
            if check_password_hash(row[2], data["password"]):
                return {"message": "logged in!"}, 200
            else:
                return {"message": "invalid password"}, 401
        return {"message": "user does not exist"}


api = Api(app)
db = SQLAlchemy(app)
db.engine.execute(table_query)
api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
app.run(host="0.0.0.0", debug=True, port=int(os.environ.get('PORT', 33507)))
