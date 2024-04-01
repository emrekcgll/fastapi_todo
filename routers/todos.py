from fastapi import APIRouter, Depends, HTTPException, Path
from typing import Annotated
from sqlalchemy.orm import Session
from starlette import status
from pydantic import BaseModel, Field
from models import Todos
from database import SessionLocal
from .auth import get_current_user

router = APIRouter(tags=['Todo'], prefix='/todos')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_depenceny = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get("/", status_code=200)
async def get_all(db: db_depenceny):
    return db.query(Todos).all()


@router.get("/{id}", status_code=200)
async def get(db: db_depenceny, id: int = Path(gt=0)):
    data = db.query(Todos).filter(Todos.id == id).first()
    if data is not None:
        return data
    raise HTTPException(status_code=404, detail="Todo not found!")


class TodoSchema(BaseModel):
    title: str = Field(min_length=2)
    description: str = Field(max_length=100)
    complete: bool = Field(default=False)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create(user: user_dependency, db: db_depenceny, request: TodoSchema):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    data = Todos(**request.model_dump(), user_id=user.get('user_id'))
    db.add(data)
    db.commit()


@router.put("/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def update(user: user_dependency, db: db_depenceny, request: TodoSchema, id: int = Path(gt=0)):
    data = db.query(Todos).filter(Todos.id == id, Todos.user_id == user.get('id')).first()
    if data is None:
        raise HTTPException(status_code=404, detail="Todo not found!")

    data.title = request.title
    data.description = request.description
    data.complete = request.complete

    db.add(data)
    db.commit()


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(user: user_dependency, db: db_depenceny, id: int = Path(gt=0)):
    data = db.query(Todos).filter(Todos.id == id, Todos.user_id == user.get('id'))
    if data is None:
        raise HTTPException(status_code=404, detail="Todo not found!")

    data.delete()
    db.commit()
