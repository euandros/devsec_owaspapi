from typing import List
from models import Task
from models import User
from fastapi import status
from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from database import engine, Base, get_db
from fastapi.openapi.utils import get_openapi
from fastapi import FastAPI, Depends, HTTPException
from schemas import TaskRequest, TaskResponse, TaskListResponse
from schemas import UserRequest, UserResponse, UserUpdateRequest

Base.metadata.create_all(bind=engine)

app = FastAPI()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="API de Tarefas Vansor",
        version="1.0.0",
        description="API REST para gerenciamento de tarefas.",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.post("/usuarios", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def criar_usuario(usuario: UserRequest, db: Session = Depends(get_db)):
    db_usuario = User(**usuario.model_dump())
    db.add(db_usuario)
    db.commit()
    db.refresh(db_usuario)
    return db_usuario

@app.put("/usuarios/{usuario_id}", response_model=UserResponse)
def atualizar_usuario(usuario_id: int, usuario: UserUpdateRequest, db: Session = Depends(get_db)):
    db_usuario = db.query(User).filter(User.id == usuario_id).first()

    if db_usuario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")

    for key, value in usuario.model_dump(exclude_unset=True).items(): # Exclui campos não definidos na requisição
        setattr(db_usuario, key, value)

    db.commit()
    db.refresh(db_usuario)
    return db_usuario

@app.delete("/usuarios/{usuario_id}", status_code=status.HTTP_204_NO_CONTENT)
def excluir_usuario(usuario_id: int, db: Session = Depends(get_db)):
    db_usuario = db.query(User).filter(User.id == usuario_id).first()

    if db_usuario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")

    db.delete(db_usuario)
    db.commit()
    return None
@app.get("/healthcheck")
def healthcheck(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1")) # Use text() aqui
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e}")

@app.post("/tarefas", response_model=TaskResponse)
def criar_tarefa(tarefa: TaskRequest, db: Session = Depends(get_db)):
    db_tarefa = Task(**tarefa.model_dump())
    db.add(db_tarefa)
    db.commit()
    db.refresh(db_tarefa)
    return db_tarefa

@app.get("/tarefas", response_model=List[TaskResponse])
def listar_tarefas(db: Session = Depends(get_db)):
    tarefas = db.query(Task).all()
    return tarefas

@app.put("/tarefas/{tarefa_id}", response_model=TaskResponse)
def atualizar_tarefa(tarefa_id: int, tarefa: TaskRequest, db: Session = Depends(get_db)):
    try:
        db_tarefa = db.query(Task).filter(Task.id == tarefa_id).first()
        db.commit()
        db.refresh(db_tarefa)
        return db_tarefa
    except IntegrityError as e:
        if "tasks_user_id_fkey" in str(e):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuário não encontrado")
        raise

    if db_tarefa is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarefa não encontrada")

    # Atualiza os campos da tarefa
    for key, value in tarefa.model_dump().items():
        setattr(db_tarefa, key, value)

    db.commit()
    db.refresh(db_tarefa)
    return db_tarefa
@app.delete("/tarefas/{tarefa_id}", status_code=status.HTTP_204_NO_CONTENT)
def excluir_tarefa(tarefa_id: int, db: Session = Depends(get_db)):
    db_tarefa = db.query(Task).filter(Task.id == tarefa_id).first()

    if db_tarefa is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tarefa não encontrada")

    db.delete(db_tarefa)
    db.commit()
    return None