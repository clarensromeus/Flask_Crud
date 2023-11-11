# external imports of resources
from flask import Flask, request, redirect, url_for, render_template, jsonify, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

# flask_jwt and sqlalquemy imports of resources
from flask_jwt_extended import create_access_token,  get_jwt_identity
from flask_jwt_extended import JWTManager, jwt_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, String, Integer, DateTime

# internally crafted imports  of resources
from forms.signin import signinValidation
from forms.signup import signupValidation
from forms.createproduct import productValidation


load_dotenv()


app = Flask(__name__)

app.config["ENV"] = os.getenv("ENV_V")
app.secret_key = "fkdfdkfdkfdkfdk"
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRETE_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQL_ALQUEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv(
    "SQL_ALQUEMY_TRACK_MODIFICATION")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)
db = SQLAlchemy(app)


# User model to construct and manage data
class User(db.Model):
    __tablename__ = "users"
    id = Column("id", Integer, primary_key=True)
    Firstname = Column(String(200), nullable=False)
    Lastname = Column(String(200), nullable=False)
    Password = Column(String(200), nullable=False)
    Email = Column(String(200), unique=True, nullable=False)

    @property
    def password_hashing(self):
        raise AttributeError("sorry  password is not a readable attribute")

    @password_hashing.setter
    def password_hashing(self, newPassword):
        self.Password = generate_password_hash(
            newPassword, method="pbkdf2:sha1", salt_length=20)

    def verify_password(self, newPassword):
        return check_password_hash(self.Password, newPassword)


#  product model to construct and manage data
class Product(db.Model):
    __tablename__: "products"
    id = Column("id", Integer, primary_key=True)
    ProductName = Column(String(200), nullable=False, unique=True)
    Price = Column(String(200), nullable=False)
    created_At = Column(DateTime, default=datetime.utcnow)


# applications route and logics
@app.route("/")
def hello_world():
    return render_template("home.html"), 200


@app.route("/allusers")
def allUsers():
    users = User.query.all()
    return render_template("users.html", users=users)


@app.route("/signin", methods=["GET", "POST"])
def signIn():
    if request.method == "POST":
        form = signinValidation(request.form)
        if form.validate():
            try:
                Email = request.form["Email"]
                password = request.form["Password"]

                user = User.query.filter_by(Email=Email).first()

                if user is None:
                    return jsonify({"message": "bad credentials", "success": False})

                is_user_verify = user.verify_password(password)

                if Email != user.Email or is_user_verify is False:
                    return jsonify({"message": "bad credentials", "success": False})

                access_token = create_access_token(
                    identity=Email, expires_delta=datetime.time)

                session["user"] = access_token

                return redirect("/products")
            except Exception as error:
                return f"error : {error}"

    else:
        return render_template("signin.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        form = signupValidation(request.form)
        if form.validate():
            Firstname = request.form["Firstname"]
            Lastname = request.form["Lastname"]
            Email = request.form["Email"]
            Password = request.form["Password"]

            is_user_exist = User.query.filter_by(Email=Email).first()

            if is_user_exist is not None:
                userFirstname = is_user_exist.Firstname
                userLastname = is_user_exist.Lastname
                return f"sorry {userFirstname} {userLastname} you're alrady registered"
            else:
                user = User(Firstname=Firstname, Lastname=Lastname,
                            Email=Email, Password=Password)

                user.password_hashing = Password
                db.session.add(user)
                db.session.commit()

            return f"password : {Password} Email : {Email} ", 200
    else:
        return render_template("signin.html")


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(code="jwt-expired", err="sorry token is expired"), 401


@app.route("/userinfo", methods=["GET"])
@jwt_required()
def userInfo():
    try:
        current_user_info = get_jwt_identity()
        response = make_response(render_template(
            "user.html", userInfo=current_user_info))
        # recover the user authentification token from the session and pass it on
        # to the header in the response
        userSession = session["user"]

        response.headers["authorization"] = "Bearer {}".format(userSession)
    except Exception as error:
        return f"error : {error}"


@app.route("/products", methods=["GET", "POST"])
def products():
    if request.method == "POST":
        form = productValidation(request.form)
        if form.validate():
            try:
                ProductName = request.form["ProductName"]
                Price = request.form["Price"]

                Products = Product(ProductName=ProductName, Price=Price)
                db.session.add(Products)
                db.session.commit()
                return redirect(url_for("message", info="create"))
            except Exception as error:
                return f"error : {error}"
    else:
        allproducts = Product.query.all()
        return render_template("product.html", products=allproducts)


@app.route("/oneproduct/<string:product_id>")
@jwt_required(refresh=True)
def oneProduct(product_id):
    if product_id is not None:
        try:
            product = Product.query.filter_by(id=product_id)
            return jsonify({"product": product}), 200
        except Exception as error:
            return f"error : {error}"


@app.route("/product/update/<int:product_id>", methods=["GET", "POST"])
def editProduct(product_id):

    product = Product.query.filter_by(id=product_id).first_or_404()

    if request.method == "POST":
        if product_id is not None:
            try:
                Price = request.form.get("Price")
                product.Price = Price
                db.session.commit()
                return redirect(url_for("message", info="edit")), 200
            except Exception as error:
                return f"error : {error}"
    else:
        return render_template("update.html", product=product)


@app.route("/product/delete/<int:product_id>")
def deleteProduct(product_id):
    if product_id != None:
        try:
            product = Product.query.filter_by(id=product_id).first()
            db.session.delete(product)
            db.session.commit()
            return redirect(url_for("message", info="delete"))
        except Exception as error:
            return f"error : {error}"


@app.errorhandler(404)
def page_not_found(error):
    return f'This page does not exist {error}', 404


@app.route("/message<info>")
def message(info):
    return render_template("info.html", message=info), 200


@app.route("/logout")
def logout():
    try:
        session.pop("user")
        return redirect("/signin"), 200
    except Exception as error:
        return "error : {error}"


if __name__ == "__main__":
    db.create_all()
    db.session.commit()
    app.run(port=5000, debug=True)
