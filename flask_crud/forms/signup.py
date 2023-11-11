from wtforms import Form, StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Regexp, Length, Email


class signupValidation(Form):
    Firstname: StringField("Firstname", validators=[DataRequired("password is required"), Length(
        min=5, max=30, message="Firstname must be greater than five and less than 40")])
    Lastname: StringField("Lastname", validators=[DataRequired("Firstname is required"), Length(
        min=5, max=30, message="Lastname must be greater than five and less than 40")])
    Email: EmailField("Email", validators=[DataRequired(
        "email must not be empty"), Email("enter a correct email")])
    Password: PasswordField("Password", validators=[DataRequired(
        "Password must not be empty"), Regexp("^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$")])
