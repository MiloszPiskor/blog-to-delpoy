from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.fields.simple import PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm for Creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField(label="Submit Post")


# WTForm for Registering new users
class RegisterForm(FlaskForm):
    name = StringField(label = "Name", validators=[DataRequired()])
    email = StringField(label = 'E-mail', validators = [DataRequired(), Email()])
    password = PasswordField(label = 'Password', validators = [DataRequired(), Length(min = 8, message=" Password must be at least 8 characters long.")])
    submit = SubmitField(label="Register")


# WTForm for logging into the
class LoginForm(FlaskForm):
    email = StringField(label='E-mail', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=8,                                                                 message=" Password must be at least 8 characters long.")])
    submit = SubmitField(label="Login")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField(label="Post")