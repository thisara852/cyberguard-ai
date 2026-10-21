import pytest
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from app.core.database import SessionLocal, Base, engine
from app.models.entities import User, RoleEnum, AuditLog
from app.services.auth_service import authenticate_user, register_user, seed_default_users
from app.schemas.auth import UserRegister

def setup_module(module):
    """Setup test database tables and seed users."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_default_users(db)
    db.close()

def test_password_hashing():
    pwd = "SecretPassword!123"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

def test_jwt_token_generation():
    payload = {"sub": "analyst", "role": "Security Analyst", "id": 2}
    token = create_access_token(payload)
    assert token is not None
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "analyst"
    assert decoded["role"] == "Security Analyst"

def test_seeded_users():
    db = SessionLocal()
    admin = authenticate_user(db, "admin", "Admin@123")
    assert admin is not None
    assert admin.role == RoleEnum.SUPER_ADMIN

    analyst = authenticate_user(db, "analyst", "Analyst@123")
    assert analyst is not None
    assert analyst.role == RoleEnum.SECURITY_ANALYST

    operator = authenticate_user(db, "operator", "Operator@123")
    assert operator is not None
    assert operator.role == RoleEnum.NORMAL_USER
    db.close()

def test_user_registration_and_audit():
    db = SessionLocal()
    db.query(User).filter((User.username == "john_doe") | (User.email == "john@example.com")).delete()
    db.commit()
    user_data = UserRegister(
        username="john_doe",
        email="john@example.com",
        password="Password123!",
        full_name="John Doe",
        role=RoleEnum.NORMAL_USER
    )
    user = register_user(db, user_data, ip_address="192.168.1.50")
    assert user.id is not None
    assert user.username == "john_doe"

    # Verify audit log was recorded
    audit = db.query(AuditLog).filter(AuditLog.username == "john_doe").first()
    assert audit is not None
    assert audit.action == "USER_REGISTRATION"
    assert audit.ip_address == "192.168.1.50"
    db.close()

if __name__ == "__main__":
    setup_module(None)
    test_password_hashing()
    print("✓ Password hashing test passed")
    test_jwt_token_generation()
    print("✓ JWT token test passed")
    test_seeded_users()
    print("✓ Seeded users test passed")
    test_user_registration_and_audit()
    print("✓ User registration and audit log test passed")
    print("All Day 1 tests passed successfully!")
