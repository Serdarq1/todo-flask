from flask import Flask, jsonify, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, DateTime, case
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

import os
from datetime import datetime

app = Flask(__name__)

API = "SecretAPIKey"
app.config["SECRET_KEY"] = "şwlmefsgdptme4r23pqo"

#Login User
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class Base(DeclarativeBase):
    pass

def get_db_uri():
    uri = os.getenv("DATABASE_URL")
    if uri:
        # Render may provide postgres://, but SQLAlchemy expects postgresql://
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        return uri
    # local dev fallback
    return "sqlite:///todos.db"


# Connect Databse
app.config["SQLALCHEMY_DATABASE_URI"] = get_db_uri()
db = SQLAlchemy(model_class=Base)
db.init_app(app)

#TABLES

class Todos(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    notes: Mapped[str] = mapped_column(String(250), unique=False, nullable=True)
    is_done: Mapped[str] = mapped_column(Boolean,nullable=False)
    due_date: Mapped[str] = mapped_column(DateTime, nullable=True)
    priority: Mapped[str] = mapped_column(String(250), nullable=True)
    section: Mapped[str] =  mapped_column(String(250), nullable=False)
    created_ad: Mapped[str] = mapped_column(DateTime,nullable=False)
    updated_ad: Mapped[str] = mapped_column(DateTime, nullable=True)



class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(250), unique=False, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('./login.html')
    elif request.method == "POST":
        email = request.form.get('email')
        password = request.form.get("password")

        email = User.query.filter_by(email=email).first()

        if email and check_password_hash(email.password, password):
            login_user(email)
            return redirect(url_for("dashboard"))
        else:
            return jsonify({'Wrong password': 'Your password is incorrect'})
        

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('./register.html')
    elif request.method == "POST":
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password-confirm')
        hashed = generate_password_hash(password, salt_length=8, method='scrypt')
        
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if user:
            return jsonify({'User Exists': 'This user already exists.'})
        elif password != password_confirm:
            return jsonify({'Password Error': 'Passwords do not match.'})
        else:
            new_user = User(
                username = username,
                email = email,
                password = hashed
            )
            db.session.add(new_user)
            db.session.commit()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    if request.method == "GET":
        daily  = Todos.query.filter_by(section="daily").order_by(Todos.created_ad.desc()).all()
        weekly = Todos.query.filter_by(section="weekly").order_by(Todos.created_ad.desc()).all()
        later  = Todos.query.filter_by(section="later").order_by(Todos.created_ad.desc()).all()

        prio_list = case((Todos.priority == "high", 0), (Todos.priority == "medium", 1), (Todos.priority == "low", 2), else_=3)
        by_importance = (Todos.query.order_by(prio_list, Todos.created_ad.desc()).all())

        return render_template('./dashboard.html', daily=daily, weekly=weekly, later=later, by_importance=by_importance)
    elif request.method == "POST":
        title = request.form.get('title')
        notes = request.form.get('notes')
        section = request.form.get('section')
        priority = request.form.get('priority')

        new_todo = Todos(
            title=title,
        notes=notes,
        is_done=False,
        due_date=None,          
        priority=priority,
        section=section,
        created_ad=datetime.utcnow(),
        updated_ad=datetime.utcnow(),
        )

        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
@app.route('/delete/<int:todo_id>')
@login_required
def delete_todo(todo_id):
    todo_to_delete = db.get_or_404(Todos, todo_id)
    db.session.delete(todo_to_delete)
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run()