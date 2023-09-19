from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = StringField('Email')
    password = PasswordField('Password')
    name = StringField('Name')
    button = SubmitField('Sign me up!')

# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Log in')

# TODO: Create a CommentForm so users can leave comments below posts
class PostForm(FlaskForm):
    comment = CKEditorField('Comment', render_kw={"class": "ckeditor-field"})
    submit = SubmitField('Submit Comment', render_kw={"class": "submit-button"})