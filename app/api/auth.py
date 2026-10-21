from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import timedelta

from app.core.database import get_db
from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models.entities import User
from app.schemas.auth import (
    UserRegister, UserLogin, TokenResponse, UserResponse, PasswordChange, UserProfileUpdate
)
from app.services.auth_service import authenticate_user, register_user, get_current_user
from app.services.audit_service import log_action

router = APIRouter(prefix="/auth", tags=["Authentication & User Management"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserRegister, request: Request, db: Session = Depends(get_db)):
    """FR-01: Register a new user account."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = register_user(db, user_in, ip_address=client_ip)
    return user

@router.post("/login", response_model=TokenResponse)
def login(login_in: UserLogin, request: Request, db: Session = Depends(get_db)):
    """FR-02: Authenticate registered user and issue JWT access token."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = authenticate_user(db, login_in.username, login_in.password)
    if not user:
        # Record failed login attempt for audit / brute force detection
        log_action(
            db,
            username=login_in.username,
            action="LOGIN_FAILED",
            resource_type="AUTH",
            details="Invalid username or password",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Audit successful login
    log_action(
        db,
        username=user.username,
        action="LOGIN_SUCCESS",
        resource_type="AUTH",
        details=f"User {user.username} logged in successfully",
        ip_address=client_ip,
        user_id=user.id
    )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "id": user.id},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """FR-04: View current user profile information."""
    return current_user

@router.put("/profile", response_model=UserResponse)
def update_profile(
    profile_in: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-04: Update permitted user profile details."""
    if profile_in.full_name:
        current_user.full_name = profile_in.full_name
    if profile_in.email:
        # Check uniqueness
        exists = db.query(User).filter(User.email == profile_in.email, User.id != current_user.id).first()
        if exists:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = profile_in.email
    db.commit()
    db.refresh(current_user)
    return current_user

@router.post("/change-password")
def change_password(
    pwd_in: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-05: Secure password change workflow."""
    if not verify_password(pwd_in.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    current_user.hashed_password = hash_password(pwd_in.new_password)
    db.commit()

    log_action(
        db,
        username=current_user.username,
        action="PASSWORD_CHANGE",
        resource_type="USER",
        resource_id=str(current_user.id),
        details="User successfully changed password",
        user_id=current_user.id
    )
    return {"message": "Password successfully updated"}
