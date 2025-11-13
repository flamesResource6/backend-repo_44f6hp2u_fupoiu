"""
Database Schemas for Recruitment Management App

Each Pydantic model represents a MongoDB collection.
Class name lowercased is the collection name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

RoleType = Literal["superadmin", "lead", "employee"]
StatusType = Literal["Open", "Closed"]

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    role: RoleType = Field(..., description="User role")
    password_hash: str = Field(..., description="Hashed password")
    lead_id: Optional[str] = Field(None, description="For employees: the team lead's user id")
    is_active: bool = Field(True, description="Whether user is active")

class Requirement(BaseModel):
    client_domain: str
    assigned_skill: str
    ecms_id: str = Field(..., description="ECMS ID / Job ID")
    required_experience: str
    required_location: str
    assigned_budget: str
    openings: int = Field(..., ge=0, description="Number of openings")
    profiles_submitted: int = Field(0, ge=0)
    status: StatusType = Field("Open")
    recruiter_name: Optional[str] = None
    team_lead_remarks: Optional[str] = None
    assigned_employee_ids: List[str] = Field(default_factory=list, description="Employees assigned to this requirement")
    lead_id: Optional[str] = Field(None, description="Team lead who owns this requirement")

class Submission(BaseModel):
    requirement_id: str
    employee_id: str
    notes: Optional[str] = None
    count: int = Field(1, ge=1, description="Number of profiles submitted in this action")

class Remark(BaseModel):
    requirement_id: str
    author_id: str
    text: str
    remark_type: Literal["remark", "issue"] = Field("remark")

class Token(BaseModel):
    user_id: str
    token: str
    expires_at: datetime
