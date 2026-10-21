from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.models.entities import User
from app.services.auth_service import get_current_user
from app.services.assistant_service import ai_assistant

router = APIRouter(prefix="/assistant", tags=["AI Security Assistant"])

class QueryRequest(BaseModel):
    query: str

@router.post("/ask")
def query_ai_copilot(
    req: QueryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """FR-37, FR-38: Ask natural language questions to the AI Security Assistant."""
    return ai_assistant.process_query(req.query, db)
