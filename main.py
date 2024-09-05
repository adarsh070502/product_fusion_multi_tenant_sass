import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv, dotenv_values
from sqlalchemy import func
import resend

# loading variables from .env file
load_dotenv()

# accessing and printing value
RESEND_API_KEY = os.getenv("resend_api_key")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'production-fusion-assignment'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost:5432/product_fusion_assignment'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user is None:
        pass
    return user


# Models
class Organisation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)
    personal = db.Column(db.Boolean, default=False, nullable=True)
    settings = db.Column(db.JSON, default={}, nullable=True)
    created_at = db.Column(db.BigInteger, nullable=True)
    updated_at = db.Column(db.BigInteger, nullable=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    profile = db.Column(db.JSON, default={}, nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)
    settings = db.Column(db.JSON, default={}, nullable=True)
    created_at = db.Column(db.BigInteger, nullable=True)
    updated_at = db.Column(db.BigInteger, nullable=True)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organisation.id', ondelete='CASCADE'), nullable=False)


class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organisation.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.Integer, nullable=False, default=0)
    settings = db.Column(db.JSON, default={}, nullable=True)
    created_at = db.Column(db.BigInteger, nullable=True)
    updated_at = db.Column(db.BigInteger, nullable=True)


def add_user_to_user_table(email, password):
    hash_and_salted_password = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    new_user = User(
        email=email,
        password=hash_and_salted_password,
        status=1,
        created_at=int(datetime.now().timestamp()),
        updated_at=int(datetime.now().timestamp())
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user


def add_user_to_organization_table(organization_name):
    organization = Organisation.query.filter_by(name=organization_name).first()
    if not organization:
        organization = Organisation(
            name=organization_name,
            status=1,
            created_at=int(datetime.now().timestamp()),
            updated_at=int(datetime.now().timestamp())
        )
        db.session.add(organization)
        db.session.commit()
    return organization


def add_role_to_role_table(role_name, description, organization_id):
    role = Role.query.filter_by(name=role_name, org_id=organization_id).first()
    if not role:
        role = Role(
            name=role_name,
            description=description,
            org_id=organization_id
        )
        db.session.add(role)
        db.session.commit()
    return role


def add_member_to_member_table(user, organization, role):
    member = Member(
        org_id=organization.id,
        user_id=user.id,
        role_id=role.id,
        status=1,
        created_at=int(datetime.now().timestamp()),
        updated_at=int(datetime.now().timestamp())
    )
    db.session.add(member)
    db.session.commit()


def send_resend_api_mail(email, subject, message):
    resend.api_key = RESEND_API_KEY

    params: resend.Emails.SendParams = {
        "from": "Adarsh <MultiTenantSass@resend.dev>",
        "to": [email],
        "subject": subject,
        "html": f"<strong>{message}</strong>",
    }

    email = resend.Emails.send(params)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        organization_name = request.form['organization_name'].lower()
        role = request.form['role'].lower()
        description = request.form['description']

        # Checking if email already exists
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            # User already exists
            return redirect(url_for('login'))

        # If email not in database, add user to database
        user = add_user_to_user_table(email, password)
        organization = add_user_to_organization_table(organization_name)
        role = add_role_to_role_table(role, description, organization.id)
        add_member_to_member_table(user, organization, role)
        send_resend_api_mail(email, subject="Successful Signup", message="You have successfully signedup with Multi Tenant Saas<br /><br />Yours Regards,<br />Adarsh")
        print("Successfully Signed up")

        return redirect(url_for('login'))


    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            return redirect(url_for('register'))
        elif not check_password_hash(user.password, password):
            return redirect(url_for('login'))
        else:
            login_user(user)
            send_resend_api_mail(email, subject="Login Alert",message="You have successfully Logged in<br /><br />Yours Regards,<br />Adarsh")
            print("Successfully Logged in")
            return redirect(url_for('home'))

    return render_template("login.html")


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        user = User.query.filter_by(email=email).first()
        if not user:
            pass
        elif not check_password_hash(user.password, current_password):
            pass
        else:
            new_hash_and_salted_password = generate_password_hash(
                new_password,
                method='pbkdf2:sha256',
                salt_length=8
            )

            user.password = new_hash_and_salted_password
            user.updated_at = int(datetime.now().timestamp())
            db.session.commit()
            print("Successfully reset password")
            send_resend_api_mail(email, subject="Password Reset Alert",message="You have successfully reset the password<br /><br />Yours Regards,<br />Adarsh")

            return redirect(url_for('login'))

    return render_template("reset_password.html")


@app.route('/update_member_role', methods=['GET', 'POST'])
def update_member_role():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        new_role = request.form['new_role']
        description = request.form["description"]

        result = User.query.filter_by(email=email).first()
        if not result:
            return redirect(url_for('register'))
        elif not check_password_hash(result.password, password):
            return redirect(url_for('login'))
        else:
            user_id = result.id
            member = Member.query.filter_by(user_id=user_id).first()
            organization_id = member.org_id
            role = add_role_to_role_table(new_role, description, organization_id)
            member.role_id = role.id

            print("Successfully updated member role")
            db.session.commit()

    return render_template("update_member_role.html")


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    print("Successfully logged out")
    return render_template("index.html")


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html")


@app.route("/Role_wise_number_of_users")
def get_role_wise_count():

    role_counts = db.session.query(Role.name, func.count(Role.id)).group_by(Role.name).all()

    if role_counts:
        return jsonify(role_counts=[{role_name: count} for role_name, count in role_counts])
    else:
        return jsonify(error={"Not Found": "No Roles"}), 404


@app.route("/Organization_wise_number_of_members")
def get_organization_wise_count():
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    if start_time and end_time:
        start_date = datetime.strptime(start_time, '%d-%m-%Y')
        end_date = datetime.strptime(end_time, '%d-%m-%Y')

        start_time = int(start_date.timestamp())
        end_time = int(end_date.timestamp())

        organization_counts = (
            db.session.query(Organisation.name, func.count(Organisation.id))
            .filter(Organisation.created_at >= start_time)
            .filter(Organisation.created_at <= end_time)
            .group_by(Organisation.name)
            .all()
        )
    else:
        organization_counts = db.session.query(Organisation.name, func.count(Organisation.id)).group_by(
            Organisation.name).all()

    if organization_counts:
        return jsonify(organization_counts=[{organization_name: count} for organization_name, count in organization_counts])
    else:
        return jsonify(error={"Not Found": "No Organizations"}), 404


@app.route("/Organisation_wise_role_wise_number_of_users")
def get_organization_wise_role_wise_count():
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    if start_time and end_time:
        start_date = datetime.strptime(start_time, '%d-%m-%Y')
        end_date = datetime.strptime(end_time, '%d-%m-%Y')

        # Convert datetime to UNIX timestamp (in seconds)
        start_time = int(start_date.timestamp())
        end_time = int(end_date.timestamp())

        # Query with time filter applied to the created_at field
        query = db.session.query(
            Organisation.name.label('organisation_name'),
            Role.name.label('role_name'),
            func.count(User.id).label('user_count')
        ).join(Role, Organisation.id == Role.org_id) \
            .join(Member, Role.id == Member.role_id) \
            .join(User, User.id == Member.user_id) \
            .filter(Member.created_at >= start_time)   \
        .filter(Member.created_at <= end_time)  \
        .group_by(Organisation.name, Role.name) \
            .order_by(Organisation.name, Role.name).all()

    else:
        query = db.session.query(
            Organisation.name.label('organisation_name'),
            Role.name.label('role_name'),
            func.count(User.id).label('user_count')
        ).join(Role, Organisation.id == Role.org_id) \
            .join(Member, Role.id == Member.role_id) \
            .join(User, User.id == Member.user_id) \
            .group_by(Organisation.name, Role.name) \
            .order_by(Organisation.name, Role.name).all()

    if query:
        return jsonify(counts=[{organization_name: {role_name: count}} for organization_name, role_name, count in query])
    else:
        return jsonify(error={"Not Found": "No Organizations"}), 404


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
