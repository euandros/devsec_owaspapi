from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr

class UserRequest(BaseModel):
    name: str
    email: EmailStr

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime | None = None # Tipo datetime
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None # Configuração para serializar datetime
        }
class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None

class TaskRequest(BaseModel):
    title: str
    description: str | None = None
    completed: bool = False
    user_id: int = Field(gt=0)

class TaskResponse(BaseModel):
    id: int
    title: str
    description: str | None = None
    completed: bool
    user_id: int
    created_at: datetime | None = None  # Aceite datetime aqui
    updated_at: datetime | None = None  # Aceite datetime aqui

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None  # Serializa datetime como string
        }

class TaskListResponse(BaseModel):
    tasks: List[TaskResponse]

    class Config:
        from_attributes = True
