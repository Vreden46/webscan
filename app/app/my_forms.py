from wtforms import StringField, IntegerField, SubmitField
from wtforms.validators import DataRequired, IPAddress, NumberRange
from flask_wtf import FlaskForm


class HostPortForm(FlaskForm):
    host = StringField('Host', validators=[DataRequired(), IPAddress()])
    portrange = StringField('Portrange', validators=[DataRequired()])
    submit = SubmitField('Submit')