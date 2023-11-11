from wtforms import Form, StringField, EmailField
from wtforms.validators import DataRequired, Email, Length


class signinValidation(Form):
    Email: EmailField("Email", validators=[DataRequired(
        "email must not be empty"), Email("enter a valid Email")])
    Password: StringField("Password", validators=[
                          DataRequired("password is required"),
                          Length(min=5, message="length must be greater than 5")
                          ])
