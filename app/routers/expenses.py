# backend/app/routers/expenses.py
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, date
from supabase import create_client
import os

from ..auth_utils import get_current_user

router = APIRouter(prefix="/expenses", tags=["Gastos"])

# Configuración de Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# ============================================
# MODELOS DE DATOS
# ============================================

class ExpenseCreate(BaseModel):
    name: str
    amount: float
    date: str  # Recibimos como string ISO
    category: str
    description: Optional[str] = None
    is_recurring: bool = False
    recurrence_pattern: Optional[str] = None

class ExpenseUpdate(BaseModel):
    name: Optional[str] = None
    amount: Optional[float] = None
    date: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    is_recurring: Optional[bool] = None
    recurrence_pattern: Optional[str] = None

class ExpenseResponse(BaseModel):
    id: str
    user_id: str
    name: str
    amount: float
    date: str
    category: str
    description: Optional[str] = None
    receipt_url: Optional[str] = None
    is_recurring: bool
    recurrence_pattern: Optional[str] = None
    created_at: str
    updated_at: str

class ExpenseStatsResponse(BaseModel):
    total: float
    count: int
    average: float

# ============================================
# FUNCIONES AUXILIARES
# ============================================

def serialize_date(date_value):
    """Convierte un objeto date a string ISO"""
    if isinstance(date_value, date):
        return date_value.isoformat()
    if isinstance(date_value, datetime):
        return date_value.isoformat()
    return date_value

def prepare_expense_data(expense_data: dict) -> dict:
    """Prepara los datos del gasto para Supabase, serializando fechas"""
    prepared = {}
    for key, value in expense_data.items():
        if key == 'date' and value:
            prepared[key] = serialize_date(value)
        elif value is not None:
            prepared[key] = value
    return prepared

# ============================================
# ENDPOINTS
# ============================================

@router.post("/", response_model=ExpenseResponse)
async def create_expense(
    expense: ExpenseCreate,
    current_user: dict = Depends(get_current_user)
):
    """Crear un nuevo gasto"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"💰 [EXPENSES] Creando gasto para: {user_email}")
    print(f"💰 Datos recibidos: {expense.model_dump()}")
    
    # Preparar datos para Supabase con serialización de fecha
    expense_data = {
        "user_id": user_id,
        "name": expense.name,
        "amount": expense.amount,
        "date": expense.date,  # Ya es string, pero usamos la función por seguridad
        "category": expense.category,
        "description": expense.description,
        "is_recurring": expense.is_recurring,
        "recurrence_pattern": expense.recurrence_pattern,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    
    # Asegurar que la fecha sea serializable
    expense_data = prepare_expense_data(expense_data)
    
    print(f"💰 Datos preparados: {expense_data}")
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        response = supabase.table("expenses").insert(expense_data).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al crear el gasto"
            )
        
        result = response.data[0]
        print(f"✅ [EXPENSES] Gasto creado: {result.get('id')}")
        
        return ExpenseResponse(
            id=result.get("id"),
            user_id=result.get("user_id"),
            name=result.get("name"),
            amount=float(result.get("amount")),
            date=result.get("date"),
            category=result.get("category"),
            description=result.get("description"),
            receipt_url=result.get("receipt_url"),
            is_recurring=result.get("is_recurring", False),
            recurrence_pattern=result.get("recurrence_pattern"),
            created_at=result.get("created_at"),
            updated_at=result.get("updated_at")
        )
        
    except Exception as e:
        print(f"❌ [EXPENSES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear gasto: {str(e)}"
        )


@router.get("/", response_model=List[ExpenseResponse])
async def get_expenses(current_user: dict = Depends(get_current_user)):
    """Obtener todos los gastos del usuario"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"💰 [EXPENSES] Obteniendo gastos para: {user_email}")
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        response = supabase.table("expenses").select("*").eq("user_id", user_id).order("date", desc=True).execute()
        
        expenses = []
        for row in response.data:
            expenses.append(ExpenseResponse(
                id=row.get("id"),
                user_id=row.get("user_id"),
                name=row.get("name"),
                amount=float(row.get("amount")),
                date=row.get("date"),
                category=row.get("category"),
                description=row.get("description"),
                receipt_url=row.get("receipt_url"),
                is_recurring=row.get("is_recurring", False),
                recurrence_pattern=row.get("recurrence_pattern"),
                created_at=row.get("created_at"),
                updated_at=row.get("updated_at")
            ))
        
        print(f"✅ [EXPENSES] {len(expenses)} gastos encontrados")
        return expenses
        
    except Exception as e:
        print(f"❌ [EXPENSES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al obtener gastos"
        )


@router.put("/{expense_id}", response_model=ExpenseResponse)
async def update_expense(
    expense_id: str,
    expense: ExpenseUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar un gasto existente"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"💰 [EXPENSES] Actualizando gasto {expense_id} para: {user_email}")
    
    # Preparar datos para actualización
    update_data = expense.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow().isoformat()
    
    # Asegurar que la fecha sea serializable si está presente
    update_data = prepare_expense_data(update_data)
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        # Verificar que el gasto pertenezca al usuario
        check = supabase.table("expenses").select("id").eq("id", expense_id).eq("user_id", user_id).execute()
        
        if not check.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Gasto no encontrado"
            )
        
        response = supabase.table("expenses").update(update_data).eq("id", expense_id).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al actualizar el gasto"
            )
        
        result = response.data[0]
        print(f"✅ [EXPENSES] Gasto actualizado: {expense_id}")
        
        return ExpenseResponse(
            id=result.get("id"),
            user_id=result.get("user_id"),
            name=result.get("name"),
            amount=float(result.get("amount")),
            date=result.get("date"),
            category=result.get("category"),
            description=result.get("description"),
            receipt_url=result.get("receipt_url"),
            is_recurring=result.get("is_recurring", False),
            recurrence_pattern=result.get("recurrence_pattern"),
            created_at=result.get("created_at"),
            updated_at=result.get("updated_at")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ [EXPENSES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar gasto"
        )


@router.delete("/{expense_id}")
async def delete_expense(
    expense_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Eliminar un gasto"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"💰 [EXPENSES] Eliminando gasto {expense_id} para: {user_email}")
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        # Verificar que el gasto pertenezca al usuario
        check = supabase.table("expenses").select("id").eq("id", expense_id).eq("user_id", user_id).execute()
        
        if not check.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Gasto no encontrado"
            )
        
        response = supabase.table("expenses").delete().eq("id", expense_id).execute()
        
        print(f"✅ [EXPENSES] Gasto eliminado: {expense_id}")
        
        return {"message": "Gasto eliminado correctamente"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ [EXPENSES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar gasto"
        )


@router.get("/stats", response_model=ExpenseStatsResponse)
async def get_expense_stats(current_user: dict = Depends(get_current_user)):
    """Obtener estadísticas de gastos del usuario"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"💰 [EXPENSES] Obteniendo estadísticas para: {user_email}")
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        response = supabase.table("expenses").select("amount").eq("user_id", user_id).execute()
        
        expenses = response.data
        total = sum(float(e.get("amount", 0)) for e in expenses)
        count = len(expenses)
        average = total / count if count > 0 else 0
        
        print(f"✅ [EXPENSES] Estadísticas: total=${total}, count={count}")
        
        return ExpenseStatsResponse(
            total=total,
            count=count,
            average=average
        )
        
    except Exception as e:
        print(f"❌ [EXPENSES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al obtener estadísticas"
        )