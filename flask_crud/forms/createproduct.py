from wtforms import Form, StringField, IntegerField
from wtforms.validators import DataRequired, Length


class productValidation(Form):
    ProductName: StringField("ProductName", validators=[DataRequired("ProductName is required"), Length(
        min=6, max=30, message="ProductName must be greater than six and less than 30")])
    Price: IntegerField("Price", validators=[
                        DataRequired("Price is required")])
