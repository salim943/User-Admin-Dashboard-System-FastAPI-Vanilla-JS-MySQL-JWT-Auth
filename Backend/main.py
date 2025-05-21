from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.hash import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pydantic import BaseModel

# ─────────────────────────────────────────────
# CONFIGURATION
SECRET_KEY = "supersecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ─────────────────────────────────────────────
# DATABASE SETUP
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://username:password@host_name:port_number/db_name"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ─────────────────────────────────────────────
# DATABASE MODEL
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)  # length needed!
    hashed_password = Column(String(128))                   # length needed!
    role = Column(String(50)) 

Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────────
# FASTAPI SETUP
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# SCHEMAS
class SignupRequest(BaseModel):
    username: str
    password: str
    role: str = "user"  # Allow setting role during signup (optional)

# ─────────────────────────────────────────────
# UTILITY FUNCTIONS
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(password: str, hashed_password: str):
    return bcrypt.verify(password, hashed_password)

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def require_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ─────────────────────────────────────────────
# Create admin user on startup if not exists
@app.on_event("startup")
def create_initial_admin():
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                hashed_password=bcrypt.hash("password"),  # Change to strong secure password!
                role="admin"
            )
            db.add(admin_user)
            db.commit()
            print("Admin user created with username='admin' and password='adminpassword'")
    finally:
        db.close()

# ─────────────────────────────────────────────
# ROUTES

@app.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    existing = get_user_by_username(db, request.username)
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    # Force role to "user" if someone tries to signup as admin through this route
    role = "user"
    user = User(
        username=request.username,
        hashed_password=bcrypt.hash(request.password),
        role=role
    )
    db.add(user)
    db.commit()
    return {"msg": "User created successfully"}

@app.post("/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_username(db, form.username)
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}

# ─────────────────────────────────────────────
# ADMIN-ONLY ROUTES

@app.get("/admin/users", dependencies=[Depends(require_admin)])
def list_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in users]

@app.delete("/admin/users/{username}", dependencies=[Depends(require_admin)])
def delete_user(username: str, db: Session = Depends(get_db)):
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"msg": f"User '{username}' deleted successfully"}
