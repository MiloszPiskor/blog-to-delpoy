from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, inspect
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import logging
from dotenv import load_dotenv
import os

def _url_has_allowed_host_and_scheme(url, allowed_hosts, require_https=False):
    if url is not None:
        url = url.strip()

    if not url:
        return False

    if allowed_hosts is None:
        allowed_hosts = set()
    elif isinstance(allowed_hosts, str):
        allowed_hosts = {allowed_hosts}

    # Normalize the path by replacing backslashes with forward slashes
    normalized_url = url.replace('\\', '/')

    return True

def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return jsonify(error = "Unauthorized access"), 401
    return wrapper_function

load_dotenv()
app = Flask(__name__)
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)
# sceret_key = token_hex()
# print(f"This is this session's secret key: {sceret_key}")

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"Please login first."


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# SETTING UP GRAVATAR
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="blog_post")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    comment_author= relationship("User", back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)
    # RELATIONSHIP OF One To Many Between Blog Post sand Comment
    blog_post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    blog_post= relationship("BlogPost", back_populates="comments")


with app.app_context():
    if not inspect(db.engine).has_table("users"):
        app.logger.error("The 'user' table does not exist.")
    else:
        app.logger.info("User table exists and is ready for queries.")

with app.app_context():
    app.logger.info(f"Registered routes: {[rule.rule for rule in app.url_map.iter_rules()]}")

with app.app_context():
    db.create_all()
    # new_user = User(email="admin@example.com", password=generate_password_hash("hashed_password", method='pbkdf2:sha256', salt_length=8), name="Admin")
    # db.session.add(new_user)
    # db.session.commit()

# with app.app_context():
#     user = User.query.first()  # Retrieve an existing user from the database
#
# if user:
#     # Create a new blog post linked to the user
#     with app.app_context():
#         new_post = BlogPost(
#             title="Test Post",
#             subtitle="Test Subtitle",
#             date="January 22, 2025",
#             body="This is a test blog post.",
#             img_url="https://example.com/image.jpg",
#         )
#
#         db.session.add(new_post)
#         db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get_or_404(user_id)

@app.route('/register', methods=["POST", "GET"])
def register():

    form = RegisterForm()
    if form.validate_on_submit():
        app.logger.info("Form successfully submitted.")
        # check_for_user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar_one_or_none()
        check_for_user = User.query.filter_by(email=form.email.data).first()
        if check_for_user:
            flash("You are already registered in our database. Please log in.")
            email = form.email.data
            return redirect(url_for("login", email= email))
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)

        new_user = User( name = form.name.data, email = form.email.data, password = hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f"New user {new_user.name} added to the database.")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error occurred while adding user: {str(e)}")

        login_user(new_user)
        flash("You've been successfully registered!", category="success")

        return redirect(url_for("get_all_posts"))


    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():

    email = request.args.get("email")
    if email:
        form = LoginForm(
            email = email
        )
    else:
        form = LoginForm()

    if form.validate_on_submit():

        user_to_log = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar_one_or_none()
        if user_to_log:
            if check_password_hash(pwhash=user_to_log.password, password =form.password.data):
                login_user(user_to_log)
                flash("Successfully logged in!", category="success")

                # Default to 'get_all_posts' path
                next_url = url_for("get_all_posts")
                # Override next_url if it's valid
                captured_url = request.args.get('next')
                # Ensure next_url is safe and valid, otherwise fallback
                if captured_url and _url_has_allowed_host_and_scheme(next_url, request.host):
                    next_url = current_user
                    app.logger.info(f"The captured url for unauthorized entry has been fetched. Redirecting to: {next_url}...")

                return redirect(next_url)
            else:
                flash("Wrong password!")
                return redirect(url_for("login"))
        else:
            flash(f"No user with email: '{form.email.data}' found!")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)

@login_required
@app.route('/logout')
def logout():

    logout_user()
    app.logger.info("User successfully logged out.")
    flash("You've been successfully logged out.", category="success")
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():

    # request_data = request.args
    # for key in request_data:
    #     flash(request_data[key])
    # if request.args.get("message_register"):
    #     flash(request_data["message_register"])
    try:
        all_posts = BlogPost.query.all() # ALREADY RETURNS A LIST
    except Exception as e:
        app.logger.error(f"Error occurred while fetching blog posts: {e}")
        flash(f"An error occurred: {e}", category="error")
        return redirect(url_for("get_all_posts"))

    return render_template("index.html", all_posts=all_posts)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):

    # FOR GET REQUEST:
    post = db.get_or_404(BlogPost, post_id)
    print(f"Debug statement for func: {show_post.__name__}. Post nr: {post.id} is about {post.body}")

    comment_form = CommentForm()
    # all_comments = Comment.query.all()
    # IF COMMENT POSTED:
    if comment_form.validate_on_submit():
        # author = db.get_or_404(User, current_user.get_id()) #Throws 404 when no user logged in thus making impossible to view post for unauthenticated person
        author = db.session.execute(db.select(User).where(User.id == current_user.get_id())).scalar()

        if not author:
            flash(message="You must be logged in to add comments.")
            return redirect(url_for("login"))

        else:
            new_comment = Comment(
                comment_author = author,  # TO FETCH USER.ID AS FOREIGN KEY
                text = comment_form.comment.data,
                blog_post = post          # TO FETCH BLOG_POST.ID AS FOREIGN KEY
            )
            db.session.add(new_comment)
            db.session.commit()
            logging.info(f"New comment: {new_comment.id} being added! The author: {author.name} wrote for post nr.: {post.id}")
            return redirect(url_for("show_post", post_id=post_id))
            # return render_template("post.html", post=post, form=comment_form, all_comments=Comment.query.all())

    return render_template("post.html", post=post, form=comment_form)

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    # user_id = current_user.get_id()
    author = db.get_or_404(User, current_user.get_id())
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=author,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        attr_to_change = edit_form.data
        for key in attr_to_change:
            setattr(post, key, attr_to_change[key])
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    deleting_post = db.get_or_404(BlogPost, post_id)
    print(f"This is a debug statement for func: {delete_post.__name__}.\nThe post: {deleting_post.title} is being deleted...")
    db.session.delete(deleting_post)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=5002)
