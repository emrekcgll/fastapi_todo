from datetime import timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from starlette import status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from dotenv import load_dotenv
import os
# from passlib.hash import bcrypt
from database import SessionLocal
from models import EmailConfirm, Users
from jose import JWTError, jwt
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import secrets

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
EMAIL = os.getenv('EMAIL')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

router = APIRouter(tags=['Authentication'], prefix='/auth')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_depenceny = Annotated[Session, Depends(get_db)]

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


class CreateUserSchema(BaseModel):
    email: str
    first_name: str
    last_name: str
    password: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_depenceny, request: CreateUserSchema):
    if db.query(Users).filter(Users.email == request.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='This email address is already exist.')

    data = Users(email=request.email,
                 first_name=request.first_name,
                 last_name=request.last_name,
                 password=bcrypt_context.hash(request.password))
    db.add(data)
    db.commit()

    token, token_expire, verification_token = await get_verification_token(data.email)
    await send_verification_email(data.email, data.first_name, verification_token)

    verification_data = EmailConfirm(
        user_id=data.id, token=token, token_expire=token_expire)
    db.add(verification_data)
    db.commit()
    raise HTTPException(status_code=status.HTTP_201_CREATED,
                        detail="Account created successfully. Please confirm your email address.")


async def get_verification_token(email):
    token = secrets.token_urlsafe(12)

    token_expire = datetime.utcnow()
    one_hour = timedelta(hours=1)
    token_expire += one_hour

    verification_params = f"?email={email}&token={token}"
    return token, token_expire, verification_params


async def send_verification_email(email, first_name, verification_token):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = EMAIL
    sender_password = EMAIL_PASSWORD

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = 'Email Confirmation'
    body = f'Dear {first_name}, Please confirm your email address.\nPlease click: http://127.0.0.1:8000/auth/confirm{verification_token}\n\nIf you are not register on this site please do not verify the link.'
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        server.quit()
    except Exception as e:
        print("An error occurred while sending verification email:", str(e))


@router.get("/confirm")
async def confirm_user_email(db: db_depenceny, email: str = Query(...), token: str = Query(...)):
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User email already active.")

    user_email_confirm_data = db.query(EmailConfirm).filter(
        EmailConfirm.user_id == user.id).first()
    current_time = datetime.utcnow()
    if not user_email_confirm_data or user_email_confirm_data.token != token or user_email_confirm_data.token_expire < current_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    user.is_active = True
    db.add(user)
    db.commit()
    db.query(EmailConfirm).filter(EmailConfirm.user_id == user.id).delete()
    db.commit()
    raise HTTPException(status_code=status.HTTP_200_OK,
                        detail="User email successfully confirmed.")


@router.post("/resend-email-confirmation")
async def resend_verification_email(db: db_depenceny, email: str):
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User email already active.")

    token, token_expire, verification_token = await get_verification_token(user.email)
    await send_verification_email(user.email, user.first_name, verification_token)
    last_verification_token = db.query(EmailConfirm).filter(
        EmailConfirm.user_id == user.id).first()
    if last_verification_token:
        db.query(EmailConfirm).filter(EmailConfirm.user_id == user.id).delete()
        db.commit()

    verification_data = EmailConfirm(
        user_id=user.id, token=token, token_expire=token_expire)
    db.add(verification_data)
    db.commit()
    raise HTTPException(status_code=status.HTTP_200_OK,
                        detail="We will send an email confirmation after a few minutes.")


class Token(BaseModel):
    access_token: str
    token_type: str


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_depenceny):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    token = create_access_token(user.email, user.id, timedelta(hours=1))
    return {'access_token': token, 'token_type': 'Bearer'}


def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.email == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.password):
        return False
    return user


def create_access_token(email: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': email, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('sub')
        id: int = payload.get('id')
        if email is None or id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return {'email': email, 'id': id}
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='JWT decoding error: ' + str(e))
