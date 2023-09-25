from datetime import date
import os
from flask import Flask, abort, render_template, redirect, url_for, flash, request, g
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from bs4 import BeautifulSoup
from forms import CreatePostForm, RegisterForm, LoginForm, PostForm
import smtplib


EMAIL = os.getenv('EMAIL')
PASSWORD = os.getenv('PASSWORD')

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('FLASK_KEY')
ckeditor = CKEditor(app)
app.config['CKEDITOR_PKG_TYPE'] = 'standard'
Bootstrap5(app)

global logged_in, user
logged_in = False


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")

db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)

    posts = relationship("BlogPost", backref='user', lazy=True)
    comments = relationship('Comment', backref='user', lazy=True)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    author = db.Column(db.String, db.ForeignKey("user.name"), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_comment = relationship("Comment", backref="blog_post", lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_post = relationship('BlogPost', backref='comment', lazy=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)



with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        name = register_form.name.data
        email = register_form.email.data

        email_list = User.query.with_entities(User.email).all()
        emails = [email[0] for email in email_list]

        if email in emails:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        password = register_form.password.data
        hash_salt_password = generate_password_hash(password=password, salt_length=8)
        user = User(email=email, password=hash_salt_password, name=name)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if current_user and current_user.id == 1:
                return f(*args, **kwargs)
            else:
                return redirect(url_for('get_all_posts'))
        except:
            return redirect(url_for('get_all_posts'))
    return decorated_function

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('incorrect password')
        else:
            flash('That email does not exist, please try again')
    return render_template("login.html", form=login_form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    if current_user.is_authenticated:
        logged_in = True
        user = User.query.get(current_user.id)
        return render_template("index.html", all_posts=posts, logged_in=logged_in, user=user)
    return render_template("index.html", all_posts=posts, user=0)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
    requested_post = db.get_or_404(BlogPost, post_id)
    form = PostForm()
    column_comment_post_id = db.session.query(Comment.text, Comment.post_id, Comment.author, Comment.id).all()
    comment_post_id_tuple_list = [(BeautifulSoup(value1, 'html.parser').get_text(), value2, value3, value4) for value1, value2, value3, value4 in column_comment_post_id]
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment_text = form.comment.data
            comment = Comment(text=comment_text, author=current_user.name, author_id=current_user.id, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash('You need to log in to comment on posts!')
            return redirect(url_for('login'))

    if current_user.is_authenticated:
        logged_in = True
        user = User.query.get(current_user.id)
        return render_template("post.html", post=requested_post, user=user, logged_in=logged_in, form=form, comment_post_id_tuple_list=comment_post_id_tuple_list, gravatar=gravatar)
    return render_template("post.html", post=requested_post, user=None, form=form, comment_post_id_tuple_list=comment_post_id_tuple_list, gravatar=gravatar)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if current_user.is_authenticated:
        logged_in = True
        if form.validate_on_submit():
            author_id = current_user.id
            new_post = BlogPost(
                author_id=author_id,
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.name,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        return render_template("make-post.html", logged_in=logged_in, form=form)
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    logged_in = True
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=logged_in)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.query(Comment).filter(Comment.post_id == post_id).delete()
    db.session.commit()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route('/delete-comment/<int:comment_id>/<int:post_id>')
@admin_only
def delete_comment(comment_id, post_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))

@app.route("/about")
def about():
    if current_user.is_authenticated:
        logged_in = True
        return render_template("about.html", logged_in=logged_in)
    return render_template("about.html")


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if current_user.is_authenticated:
        logged_in = True
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            message = request.form.get('message')
            s = smtplib.SMTP('smtp.gmail.com', 587)
            s.starttls()
            s.login(EMAIL, PASSWORD)
            s.sendmail(EMAIL, EMAIL, f'Subject:Bootstrap Blog\n\nName: {name}\n\nEmail: {email}\n\nMessage: {message}')
            s.quit()
        return render_template("contact.html", logged_in=logged_in)
    elif request.method == 'POST':
        flash('You need to be logged in to contact!')
        return redirect(url_for('login'))
    return render_template("contact.html")

@app.route('/user-information', methods=['GET'])
@admin_only
def user_info():
    logged_in=True
    email_name = User.query.with_entities(User.name, User.email).all()
    email_name_dict = {item[0]: item[1] for item in email_name}
    return render_template('user_info.html', logged_in=logged_in, user_dict=email_name_dict)



if __name__ == "__main__":
    app.run(debug=False)
