import email_validator
import wtforms.validators
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterUserForm(FlaskForm):
    email = StringField(validators=[wtforms.validators.Email(), DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    name = StringField(validators=[DataRequired()])
    submit = SubmitField("Sign Me Up")


class LoginUserForm(FlaskForm):
    email = StringField(validators=[wtforms.validators.Email(), DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField("Log In")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment Content", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
