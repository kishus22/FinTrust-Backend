from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# -----------------------
# APP CONFIGURATION
# -----------------------

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fintrust.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# -----------------------
# DATABASE MODELS
# -----------------------

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='customer')
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Account(db.Model):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    balance = db.Column(db.Float, default=1000.0)
    currency = db.Column(db.String(10), default='INR')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    sender_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    receiver_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='success')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------
# CREATE TABLES
# -----------------------

with app.app_context():
    db.create_all()

# -----------------------
# REGISTER API
# -----------------------

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 400

    hashed_password = generate_password_hash(password)

    new_user = User(
        full_name=full_name,
        email=email,
        password_hash=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    # Create account automatically
    account = Account(
        user_id=new_user.id,
        account_number=f"FT{new_user.id:06d}"
    )

    db.session.add(account)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


# -----------------------
# LOGIN API
# -----------------------

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get("email") or not data.get("password"):
        return jsonify({"message": "Email and password required"}), 400

    user = User.query.filter_by(email=data["email"]).first()

    if not user:
        return jsonify({"message": "Invalid credentials"}), 401

    if not check_password_hash(user.password_hash, data["password"]):
        return jsonify({"message": "Invalid credentials"}), 401

    # 🔥 IMPORTANT BLOCK CHECK
    if user.is_blocked:
        return jsonify({"message": "User is blocked"}), 403

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role}
    )

    return jsonify({
        "message": "Login successful",
        "access_token": access_token
    }), 200


@app.route('/transfer', methods=['POST'])
@jwt_required()
def transfer():
    user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")

    if role != "customer":
        return jsonify({"message": "Access forbidden"}), 403

    data = request.get_json()

    receiver_account_number = data.get("receiver_account_number")
    amount = data.get("amount")

    if receiver_account_number is None or amount is None:
        return jsonify({"message": "All fields are required"}), 400

    if amount <= 0:
        return jsonify({"message": "Amount must be greater than 0"}), 400

    sender_account = Account.query.filter_by(user_id=int(user_id)).first()

    receiver_account = Account.query.filter_by(
        account_number=receiver_account_number
    ).first()

    if not receiver_account:
        return jsonify({"message": "Receiver not found"}), 404

    if sender_account.id == receiver_account.id:
        return jsonify({"message": "Cannot transfer to same account"}), 400

    if sender_account.balance < amount:
        return jsonify({"message": "Insufficient balance"}), 400

    # Perform transfer
    sender_account.balance -= amount
    receiver_account.balance += amount

    # Log transaction
    transaction = Transaction(
        sender_account_id=sender_account.id,
        receiver_account_id=receiver_account.id,
        amount=amount
    )

    db.session.add(transaction)
    db.session.commit()

    return jsonify({"message": "Transfer successful"}), 200

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")

    if role != "customer":
        return jsonify({"message": "Access forbidden"}), 403

    account = Account.query.filter_by(user_id=int(user_id)).first()

    transactions = Transaction.query.filter(
        (Transaction.sender_account_id == account.id) |
        (Transaction.receiver_account_id == account.id)
    ).order_by(Transaction.created_at.desc()).all()

    result = []

    for t in transactions:
        result.append({
            "id": t.id,
            "sender_account_id": t.sender_account_id,
            "receiver_account_id": t.receiver_account_id,
            "amount": t.amount,
            "status": t.status,
            "created_at": t.created_at
        })

    return jsonify(result), 200

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    claims = get_jwt()
    role = claims.get("role")

    if role != "admin":
        return jsonify({"message": "Access forbidden"}), 403

    users = User.query.all()

    result = []
    for user in users:
        result.append({
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role,
            "is_blocked": user.is_blocked,
            "created_at": user.created_at
        })

    return jsonify(result), 200

@app.route('/block-user/<int:user_id>', methods=['PATCH'])
@jwt_required()
def block_user(user_id):
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")

    if role != "admin":
        return jsonify({"message": "Access forbidden"}), 403

    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    user.is_blocked = True
    db.session.commit()

    return jsonify({"message": "User blocked successfully"}), 200

@app.route('/me', methods=['GET'])
@jwt_required()
def get_me():
    user_id = get_jwt_identity()

    account = Account.query.filter_by(user_id=int(user_id)).first()

    return jsonify({
        "account_number": account.account_number,
        "balance": account.balance
    }), 200
# -----------------------
# RUN SERVER
# -----------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)