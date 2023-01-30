from datetime import date
import flask
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms.forms import CreatePostForm, RegisterUserForm, LoginUserForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from dotenv import load_dotenv
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
load_dotenv()

# INIT LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
uri = os.environ.get("DATABASE_URL")  # or other relevant config var

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

    def __repr__(self):
        return "<post_id> %d" % self.id


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

    def __repr__(self):
        return "<user_id> %d" % self.id


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    def __repr__(self):
        return "<comment_id> %d" % self.id


def get_all_posts():
    posts = BlogPost.query.all()
    return posts


def get_post(post_id):
    post = BlogPost.query.get(post_id)
    return post


def add_post(form, current_user):
    new_post = BlogPost(
        title=form.title.data,
        subtitle=form.subtitle.data,
        body=form.body.data,
        img_url=form.img_url.data,
        author=current_user,
        date=date.today().strftime("%B %d, %Y")
    )
    db.session.add(new_post)
    db.session.commit()


def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()


def edit_post(post_id, edit_form):
    post = BlogPost.query.get(post_id)
    post.title = edit_form.title.data
    post.subtitle = edit_form.subtitle.data
    post.img_url = edit_form.img_url.data
    post.body = edit_form.body.data
    db.session.commit()


def register_user(name, email, password):
    new_user = User(
        name=name,
        password=password,
        email=email
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user


def get_user(user_id):
    user = User.query.get(user_id)
    return user


def get_user_by_email(email):
    user = User.query.filter_by(email=email).first()
    return user


def get_user_id(user):
    return user.id


def add_comment(comment, author, post):
    new_comment = Comment(text=comment, parent_post=post, author=author)
    db.session.add(new_comment)
    db.session.commit()


def admin_only(f):
    @wraps(f)
    def d_func(*args, **kwargs):
        admin_user = get_user(1)
        if get_user_id(current_user) == 1:
            return f(*args, **kwargs)
        print(get_user_id(current_user))
        print(admin_user)
        return flask.abort(403, "forbidden")

    return d_func


@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    admin_user = False
    if current_user == get_user(1):
        admin_user = True
    return render_template("index.html", all_posts=posts, admin=admin_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        if get_user_by_email(form.email.data) is None:
            new_user = register_user(
                form.name.data,
                form.email.data,
                generate_password_hash(form.password.data, "pbkdf2:sha256", 8)
            )
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        print("Found that email in database already.")
        return redirect(url_for('login', email_error=flash("That email already exists.", "error")))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUserForm()
    if form.validate_on_submit():
        user = get_user_by_email(form.email.data)
        if user is not None:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            flash("Wrong password!", "error")
        flash("No user with that email!", "error")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    comment = None
    requested_post = None
    if current_user is not None:
        requested_post = get_post(post_id)
        comment = requested_post.comments
        print(comment)
        if form.validate_on_submit():
            add_comment(comment=form.comment.data, post=requested_post, author=current_user)
    admin_user = False
    if current_user == get_user(1):
        admin_user = True
    return render_template("post.html", post=requested_post, admin=admin_user, form=form, comment=comment)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        add_post(form, current_user=current_user)
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = get_post(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        edit_post(post_id, edit_form)
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    delete_post(post_id)
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
