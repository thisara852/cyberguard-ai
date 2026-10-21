from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List
from datetime import datetime

from app.models.entities import User, RoleEnum
from app.schemas.auth import UserRegister, PasswordChange, UserProfileUpdate
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from app.core.database import get_db
from app.services.audit_service import log_action

security_scheme = HTTPBearer(auto_error=False)

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password."""
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    
    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def register_user(db: Session, user_in: UserRegister, ip_address: str = "127.0.0.1") -> User:
    """Register a new user account (FR-01)."""
    existing_user = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Validate role
    role = user_in.role if user_in.role in [RoleEnum.SUPER_ADMIN, RoleEnum.SECURITY_ANALYST, RoleEnum.NORMAL_USER] else RoleEnum.NORMAL_USER

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        full_name=user_in.full_name or user_in.username,
        role=role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_action(
        db,
        username=new_user.username,
        action="USER_REGISTRATION",
        resource_type="USER",
        resource_id=str(new_user.id),
        details=f"User registered with role {new_user.role}",
        ip_address=ip_address,
        user_id=new_user.id
    )
    return new_user

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Validate Bearer JWT token and return active User instance (FR-02)."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing user identifier"
        )
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or not found"
        )
    return user

def require_role(allowed_roles: List[str]):
    """Role-Based Access Control dependency factory (FR-03)."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles and current_user.role != RoleEnum.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {', '.join(allowed_roles)}"
            )
        return current_user
    return role_checker

def seed_default_users(db: Session):
    """Seed default administrative, analyst, and operator accounts."""
    default_accounts = [
        ("admin", "admin@cyberguard.local", "Admin@123", "Chief Security Officer", RoleEnum.SUPER_ADMIN),
        ("analyst", "analyst@cyberguard.local", "Analyst@123", "Senior SOC Analyst", RoleEnum.SECURITY_ANALYST),
        ("operator", "operator@cyberguard.local", "Operator@123", "Security Operations", RoleEnum.NORMAL_USER)
    ]
    for username, email, pwd, name, role in default_accounts:
        if not db.query(User).filter(User.username == username).first():
            user = User(
                username=username,
                email=email,
                hashed_password=hash_password(pwd),
                full_name=name,
                role=role,
                is_active=True
            )
            db.add(user)
    db.commit()
