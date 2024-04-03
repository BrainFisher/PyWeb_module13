from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Response
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, Date, Boolean
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import date, datetime, timedelta
from typing import List, Optional
from jose import JWTError, jwt
from dotenv import dotenv_values
import cloudinary.uploader
from fastapi.responses import JSONResponse

# Визначення OAuth2 схеми
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Завантаження змінних середовища з файлу .env
env = dotenv_values(".env")

# SQLAlchemy моделі
SQLALCHEMY_DATABASE_URL = env.get("SQLALCHEMY_DATABASE_URL")
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Модель користувача


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email_verified = Column(Boolean, default=False)
    # Додали поле для зберігання URL аватара
    avatar_url = Column(String, nullable=True)

# Модель контакту


class Contact(Base):
    __tablename__ = 'contacts'

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String)
    birthday = Column(Date)
    additional_info = Column(String, nullable=True)

# Pydantic схеми


class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birthday: date
    additional_info: Optional[str] = None


class ContactCreate(ContactBase):
    pass


class ContactUpdate(ContactBase):
    pass


class Contact(ContactBase):
    id: int

    class Config:
        from_attributes = True


# FastAPI додаток
app = FastAPI()

# Залежність для отримання об'єкту сесії бази даних


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Залежність для отримання токена аутентифікації


def get_token(token: str = Depends(oauth2_scheme)):
    return token


# JWT налаштування
SECRET_KEY = env.get("SECRET_KEY")
ALGORITHM = env.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(env.get("ACCESS_TOKEN_EXPIRE_MINUTES"))

# Контекст для хешування паролів
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Генерація JWT токену


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Аутентифікація користувача


def authenticate_user(email: str, password: str, db: Session):
    user = db.query(User).filter(User.email == email).first()
    if not user or not password_context.verify(password, user.hashed_password) or not user.email_verified:
        return None
    return user

# Отримання поточного користувача з JWT токена


def get_current_user(token: str = Depends(get_token), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Конфігурація Cloudinary
cloudinary.config(
    cloud_name=env.get("CLOUDINARY_CLOUD_NAME"),
    api_key=env.get("CLOUDINARY_API_KEY"),
    api_secret=env.get("CLOUDINARY_API_SECRET")
)

# Маршрут для завантаження аватара


@app.post("/upload-avatar/")
async def upload_avatar(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Завантаження зображення на Cloudinary
    upload_result = cloudinary.uploader.upload(file.file)
    # Отримання URL зображення
    avatar_url = upload_result['secure_url']
    # Збереження URL зображення для користувача
    current_user.avatar_url = avatar_url
    db.commit()
    return {"avatar_url": avatar_url}

# Обробник помилок для HTTPException


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail}
    )

# Обробник помилок для невалідного JWT токена


@app.exception_handler(JWTError)
async def jwt_exception_handler(request, exc):
    return JSONResponse(
        status_code=401,
        content={"message": "Invalid authentication credentials"}
    )

# Ендпоінти API


@app.post("/contacts/", response_model=Contact)
def create_contact(contact: ContactCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = Contact(**contact.dict())
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact


@app.get("/contacts/", response_model=List[Contact])
def read_contacts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Contact).offset(skip).limit(limit).all()


@app.get("/contacts/{contact_id}", response_model=Contact)
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return db_contact


@app.put("/contacts/{contact_id}", response_model=Contact)
def update_contact(contact_id: int, contact: ContactUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    for key, value in contact.dict().items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact


@app.delete("/contacts/{contact_id}", response_model=Contact)
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return db_contact
