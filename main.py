import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Literal

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Requirement as RequirementSchema, Submission as SubmissionSchema, Remark as RemarkSchema

# App setup
app = FastAPI(title="Recruitment Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

Role = Literal["superadmin", "lead", "employee"]

# Utilities

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Role
    lead_id: Optional[str] = None


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: Role
    lead_id: Optional[str] = None


class RequirementCreate(BaseModel):
    client_domain: str
    assigned_skill: str
    ecms_id: str
    required_experience: str
    required_location: str
    assigned_budget: str
    openings: int
    recruiter_name: Optional[str] = None
    team_lead_remarks: Optional[str] = None


class RequirementUpdate(BaseModel):
    status: Optional[Literal["Open", "Closed"]] = None
    profiles_submitted: Optional[int] = None
    team_lead_remarks: Optional[str] = None


class Assignment(BaseModel):
    employee_id: str


class SubmissionCreate(BaseModel):
    requirement_id: str
    notes: Optional[str] = None
    count: int = 1


class RemarkCreate(BaseModel):
    requirement_id: str
    text: str
    remark_type: Literal["remark", "issue"] = "remark"


# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    user["id"] = str(user["_id"])  # type: ignore
    return user


def require_role(required: List[Role]):
    def _inner(user: dict = Depends(get_current_user)):
        if user.get("role") not in required:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient role")
        return user
    return _inner


@app.get("/")
def root():
    return {"message": "Recruitment Management API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"Error: {e}"
    return response


# Auth routes
@app.post("/auth/register", response_model=UserPublic)
def register(user: UserCreate, current: dict = Depends(require_role(["superadmin"]))):
    if db["user"].find_one({"email": user.email}):
        raise HTTPException(400, detail="Email already registered")
    doc = UserSchema(
        name=user.name,
        email=user.email,
        role=user.role,
        password_hash=hash_password(user.password),
        lead_id=user.lead_id,
        is_active=True,
    ).model_dump()
    _id = db["user"].insert_one(doc).inserted_id
    return UserPublic(id=str(_id), name=user.name, email=user.email, role=user.role, lead_id=user.lead_id)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


@app.get("/me", response_model=UserPublic)
def me(current: dict = Depends(get_current_user)):
    return UserPublic(id=str(current["_id"]), name=current["name"], email=current["email"], role=current["role"], lead_id=current.get("lead_id"))


# Users CRUD (Super Admin only)
@app.get("/users", response_model=List[UserPublic])
def list_users(current: dict = Depends(require_role(["superadmin"]))):
    users = db["user"].find({})
    return [UserPublic(id=str(u["_id"]), name=u["name"], email=u["email"], role=u["role"], lead_id=u.get("lead_id")) for u in users]


@app.delete("/users/{user_id}")
def delete_user(user_id: str, current: dict = Depends(require_role(["superadmin"]))):
    db["user"].delete_one({"_id": ObjectId(user_id)})
    return {"ok": True}


# Requirements CRUD
@app.post("/requirements")
def create_requirement(payload: RequirementCreate, current: dict = Depends(require_role(["lead", "superadmin"]))):
    req = RequirementSchema(
        client_domain=payload.client_domain,
        assigned_skill=payload.assigned_skill,
        ecms_id=payload.ecms_id,
        required_experience=payload.required_experience,
        required_location=payload.required_location,
        assigned_budget=payload.assigned_budget,
        openings=payload.openings,
        recruiter_name=payload.recruiter_name,
        team_lead_remarks=payload.team_lead_remarks,
        lead_id=str(current["_id"]) if current["role"] == "lead" else None,
    ).model_dump()
    _id = db["requirement"].insert_one(req).inserted_id
    return {"id": str(_id)}


@app.get("/requirements")
def list_requirements(current: dict = Depends(get_current_user)):
    query = {}
    if current["role"] == "employee":
        query = {"assigned_employee_ids": {"$in": [str(current["_id"]) ]}}
    elif current["role"] == "lead":
        query = {"lead_id": str(current["_id"]) }
    items = list(db["requirement"].find(query))
    for i in items:
        i["id"] = str(i["_id"])  # type: ignore
    return items


@app.patch("/requirements/{req_id}")
def update_requirement(req_id: str, payload: RequirementUpdate, current: dict = Depends(require_role(["lead", "superadmin"]))):
    update = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    db["requirement"].update_one({"_id": ObjectId(req_id)}, {"$set": update, "$currentDate": {"updated_at": True}})
    return {"ok": True}


@app.post("/requirements/{req_id}/assign")
def assign_requirement(req_id: str, data: Assignment, current: dict = Depends(require_role(["lead", "superadmin"]))):
    db["requirement"].update_one({"_id": ObjectId(req_id)}, {"$addToSet": {"assigned_employee_ids": data.employee_id}})
    return {"ok": True}


# Submissions
@app.post("/submissions")
def create_submission(payload: SubmissionCreate, current: dict = Depends(require_role(["employee", "lead", "superadmin"]))):
    if current["role"] == "employee":
        employee_id = str(current["_id"])
    else:
        employee_id = payload.__dict__.get("employee_id") or str(current["_id"])
    sub = SubmissionSchema(requirement_id=payload.requirement_id, employee_id=employee_id, notes=payload.notes, count=payload.count).model_dump()
    _id = db["submission"].insert_one(sub).inserted_id
    db["requirement"].update_one({"_id": ObjectId(payload.requirement_id)}, {"$inc": {"profiles_submitted": payload.count}})
    return {"id": str(_id)}


# Remarks / Issues
@app.post("/remarks")
def add_remark(payload: RemarkCreate, current: dict = Depends(get_current_user)):
    remark = RemarkSchema(requirement_id=payload.requirement_id, author_id=str(current["_id"]), text=payload.text, remark_type=payload.remark_type).model_dump()
    _id = db["remark"].insert_one(remark).inserted_id
    return {"id": str(_id)}


@app.get("/remarks/{req_id}")
def list_remarks(req_id: str, current: dict = Depends(get_current_user)):
    items = list(db["remark"].find({"requirement_id": req_id}))
    for i in items:
        i["id"] = str(i["_id"])  # type: ignore
    return items


# Dashboard summaries
@app.get("/dashboard/summary")
def summary(current: dict = Depends(get_current_user)):
    query = {}
    if current["role"] == "employee":
        query = {"assigned_employee_ids": {"$in": [str(current["_id"]) ]}}
    elif current["role"] == "lead":
        query = {"lead_id": str(current["_id"]) }

    total = db["requirement"].count_documents(query)
    completed = db["requirement"].count_documents({**query, "status": "Closed"})
    pending = db["requirement"].count_documents({**query, "status": "Open"})
    issues = db["remark"].count_documents({"remark_type": "issue"})

    # Simplified: count submissions
    sub_count = db["submission"].count_documents({})

    return {
        "total_requirements": total,
        "completed": completed,
        "pending": pending,
        "issues": issues,
        "team_performance": {"total_submissions": sub_count}
    }


# Seed sample data for demo
@app.post("/seed")
def seed(reset: bool = False):
    # Optional reset to force reseed
    if reset:
        for name in ["user", "requirement", "submission", "remark"]:
            try:
                db[name].drop()
            except Exception:
                pass

    # Only seed if no users
    if db["user"].count_documents({}) > 0:
        return {"ok": True, "message": "Already seeded"}

    # Create users
    super_id = db["user"].insert_one({
        "name": "Super Admin",
        "email": "admin@demo.com",
        "role": "superadmin",
        "password_hash": hash_password("admin123"),
        "is_active": True,
    }).inserted_id

    lead_id = db["user"].insert_one({
        "name": "Taylor Lead",
        "email": "lead@demo.com",
        "role": "lead",
        "password_hash": hash_password("lead123"),
        "is_active": True,
    }).inserted_id

    emp1_id = db["user"].insert_one({
        "name": "Riley Recruiter",
        "email": "emp1@demo.com",
        "role": "employee",
        "lead_id": str(lead_id),
        "password_hash": hash_password("emp123"),
        "is_active": True,
    }).inserted_id

    emp2_id = db["user"].insert_one({
        "name": "Jordan Recruiter",
        "email": "emp2@demo.com",
        "role": "employee",
        "lead_id": str(lead_id),
        "password_hash": hash_password("emp123"),
        "is_active": True,
    }).inserted_id

    # Create requirements
    r1 = db["requirement"].insert_one({
        "client_domain": "FinTech",
        "assigned_skill": "React",
        "ecms_id": "ECMS-1001",
        "required_experience": "3-5 years",
        "required_location": "Remote",
        "assigned_budget": "$80/hr",
        "openings": 2,
        "profiles_submitted": 1,
        "status": "Open",
        "recruiter_name": "Riley Recruiter",
        "team_lead_remarks": "Urgent",
        "assigned_employee_ids": [str(emp1_id)],
        "lead_id": str(lead_id)
    }).inserted_id

    r2 = db["requirement"].insert_one({
        "client_domain": "HealthTech",
        "assigned_skill": "Python",
        "ecms_id": "ECMS-1002",
        "required_experience": "5-7 years",
        "required_location": "NYC",
        "assigned_budget": "$120k",
        "openings": 1,
        "profiles_submitted": 0,
        "status": "Open",
        "recruiter_name": "Jordan Recruiter",
        "team_lead_remarks": None,
        "assigned_employee_ids": [str(emp2_id)],
        "lead_id": str(lead_id)
    }).inserted_id

    # Submissions and remarks
    db["submission"].insert_one({"requirement_id": str(r1), "employee_id": str(emp1_id), "count": 1, "notes": "Strong candidate"})
    db["remark"].insert_one({"requirement_id": str(r2), "author_id": str(lead_id), "text": "Client paused briefly", "remark_type": "issue"})

    return {"ok": True, "message": "Seeded", "credentials": {
        "superadmin": {"email": "admin@demo.com", "password": "admin123"},
        "lead": {"email": "lead@demo.com", "password": "lead123"},
        "employee1": {"email": "emp1@demo.com", "password": "emp123"},
        "employee2": {"email": "emp2@demo.com", "password": "emp123"}
    }}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
