# backend/app/routers/categories.py
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import os

from ..auth_utils import get_current_user
from ..database import get_supabase_client, get_supabase_admin

router = APIRouter(prefix="/categories", tags=["Categorías"])

# ============================================
# MODELOS DE DATOS
# ============================================

class CategoryCreate(BaseModel):
    name: str
    icon: str
    color: str

class CategoryUpdate(BaseModel):
    name: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None

class CategoryResponse(BaseModel):
    id: str
    name: str
    icon: str
    color: str
    is_default: bool
    user_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# ============================================
# CATEGORÍAS PREDEFINIDAS
# ============================================

DEFAULT_CATEGORIES = [
    {"name": "Alimentación", "icon": "🍔", "color": "#FF6B6B", "is_default": True},
    {"name": "Transporte", "icon": "🚌", "color": "#4ECDC4", "is_default": True},
    {"name": "Materiales", "icon": "📚", "color": "#45B7D1", "is_default": True},
    {"name": "Matrícula", "icon": "🎓", "color": "#96CEB4", "is_default": True},
    {"name": "Vivienda", "icon": "🏠", "color": "#FFEAA7", "is_default": True},
    {"name": "Entretenimiento", "icon": "🎬", "color": "#DDA0DD", "is_default": True},
    {"name": "Salud", "icon": "🏥", "color": "#98D8C8", "is_default": True},
    {"name": "Otros", "icon": "📦", "color": "#F7DC6F", "is_default": True},
]

# ============================================
# FUNCIONES AUXILIARES
# ============================================

async def ensure_default_categories():
    """Asegura que las categorías por defecto existan en la base de datos"""
    supabase = get_supabase_admin()
    
    for cat in DEFAULT_CATEGORIES:
        # Verificar si la categoría ya existe
        existing = supabase.table("categories").select("id").eq("name", cat["name"]).eq("is_default", True).execute()
        
        if not existing.data:
            # Insertar categoría por defecto
            supabase.table("categories").insert({
                "name": cat["name"],
                "icon": cat["icon"],
                "color": cat["color"],
                "is_default": True,
                "user_id": None,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }).execute()
            print(f"✅ [CATEGORIES] Categoría por defecto creada: {cat['name']}")

# ============================================
# ENDPOINTS
# ============================================

@router.get("/", response_model=List[CategoryResponse])
async def get_categories(current_user: dict = Depends(get_current_user)):
    """Obtener todas las categorías (por defecto + personalizadas del usuario)"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"📁 [CATEGORIES] Obteniendo categorías para: {user_email}")
    
    # Asegurar que las categorías por defecto existan
    await ensure_default_categories()
    
    supabase = get_supabase_client()
    
    # Obtener categorías por defecto
    default_response = supabase.table("categories").select("*").eq("is_default", True).execute()
    
    # Obtener categorías personalizadas del usuario
    custom_response = supabase.table("categories").select("*").eq("user_id", user_id).eq("is_default", False).execute()
    
    # Combinar resultados
    categories = []
    
    for cat in default_response.data:
        categories.append(CategoryResponse(
            id=cat.get("id"),
            name=cat.get("name"),
            icon=cat.get("icon"),
            color=cat.get("color"),
            is_default=cat.get("is_default", True),
            user_id=cat.get("user_id"),
            created_at=cat.get("created_at"),
            updated_at=cat.get("updated_at")
        ))
    
    for cat in custom_response.data:
        categories.append(CategoryResponse(
            id=cat.get("id"),
            name=cat.get("name"),
            icon=cat.get("icon"),
            color=cat.get("color"),
            is_default=cat.get("is_default", False),
            user_id=cat.get("user_id"),
            created_at=cat.get("created_at"),
            updated_at=cat.get("updated_at")
        ))
    
    print(f"✅ [CATEGORIES] {len(categories)} categorías encontradas ({len(default_response.data)} predeterminadas, {len(custom_response.data)} personalizadas)")
    
    return categories


@router.get("/default", response_model=List[CategoryResponse])
async def get_default_categories():
    """Obtener solo las categorías por defecto"""
    
    print(f"📁 [CATEGORIES] Obteniendo categorías por defecto")
    
    await ensure_default_categories()
    
    supabase = get_supabase_client()
    response = supabase.table("categories").select("*").eq("is_default", True).execute()
    
    categories = []
    for cat in response.data:
        categories.append(CategoryResponse(
            id=cat.get("id"),
            name=cat.get("name"),
            icon=cat.get("icon"),
            color=cat.get("color"),
            is_default=cat.get("is_default", True),
            user_id=cat.get("user_id"),
            created_at=cat.get("created_at"),
            updated_at=cat.get("updated_at")
        ))
    
    return categories


@router.get("/my", response_model=List[CategoryResponse])
async def get_my_categories(current_user: dict = Depends(get_current_user)):
    """Obtener solo las categorías personalizadas del usuario"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"📁 [CATEGORIES] Obteniendo categorías personalizadas para: {user_email}")
    
    supabase = get_supabase_client()
    response = supabase.table("categories").select("*").eq("user_id", user_id).eq("is_default", False).execute()
    
    categories = []
    for cat in response.data:
        categories.append(CategoryResponse(
            id=cat.get("id"),
            name=cat.get("name"),
            icon=cat.get("icon"),
            color=cat.get("color"),
            is_default=cat.get("is_default", False),
            user_id=cat.get("user_id"),
            created_at=cat.get("created_at"),
            updated_at=cat.get("updated_at")
        ))
    
    print(f"✅ [CATEGORIES] {len(categories)} categorías personalizadas encontradas")
    
    return categories


@router.post("/", response_model=CategoryResponse)
async def create_category(
    category: CategoryCreate,
    current_user: dict = Depends(get_current_user)
):
    """Crear una nueva categoría personalizada"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"📁 [CATEGORIES] Creando categoría para: {user_email}")
    print(f"   Nombre: {category.name}, Icono: {category.icon}, Color: {category.color}")
    
    # Verificar que no exista una categoría con el mismo nombre para este usuario
    supabase = get_supabase_client()
    existing = supabase.table("categories").select("id").eq("user_id", user_id).eq("name", category.name).execute()
    
    if existing.data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ya tienes una categoría llamada '{category.name}'"
        )
    
    # Verificar que no sea el mismo nombre que una categoría por defecto
    default_exists = supabase.table("categories").select("id").eq("name", category.name).eq("is_default", True).execute()
    
    if default_exists.data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ya existe una categoría por defecto llamada '{category.name}'"
        )
    
    # Crear la categoría
    category_data = {
        "user_id": user_id,
        "name": category.name,
        "icon": category.icon,
        "color": category.color,
        "is_default": False,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    
    try:
        supabase_admin = get_supabase_admin()
        response = supabase_admin.table("categories").insert(category_data).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al crear la categoría"
            )
        
        result = response.data[0]
        print(f"✅ [CATEGORIES] Categoría creada: {result.get('id')}")
        
        return CategoryResponse(
            id=result.get("id"),
            name=result.get("name"),
            icon=result.get("icon"),
            color=result.get("color"),
            is_default=result.get("is_default", False),
            user_id=result.get("user_id"),
            created_at=result.get("created_at"),
            updated_at=result.get("updated_at")
        )
        
    except Exception as e:
        print(f"❌ [CATEGORIES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear categoría: {str(e)}"
        )


@router.put("/{category_id}", response_model=CategoryResponse)
async def update_category(
    category_id: str,
    category: CategoryUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar una categoría personalizada"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"📁 [CATEGORIES] Actualizando categoría {category_id} para: {user_email}")
    
    supabase = get_supabase_client()
    
    # Verificar que la categoría existe y pertenece al usuario
    check = supabase.table("categories").select("*").eq("id", category_id).execute()
    
    if not check.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Categoría no encontrada"
        )
    
    category_data = check.data[0]
    
    # No permitir editar categorías por defecto
    if category_data.get("is_default", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No se pueden editar las categorías por defecto"
        )
    
    # Verificar que pertenece al usuario
    if category_data.get("user_id") != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para editar esta categoría"
        )
    
    # Preparar datos de actualización
    update_data = category.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow().isoformat()
    
    # Verificar que el nuevo nombre no entre en conflicto
    if "name" in update_data:
        existing = supabase.table("categories").select("id").eq("user_id", user_id).eq("name", update_data["name"]).neq("id", category_id).execute()
        
        if existing.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Ya tienes una categoría llamada '{update_data['name']}'"
            )
    
    try:
        supabase_admin = get_supabase_admin()
        response = supabase_admin.table("categories").update(update_data).eq("id", category_id).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al actualizar la categoría"
            )
        
        result = response.data[0]
        print(f"✅ [CATEGORIES] Categoría actualizada: {category_id}")
        
        return CategoryResponse(
            id=result.get("id"),
            name=result.get("name"),
            icon=result.get("icon"),
            color=result.get("color"),
            is_default=result.get("is_default", False),
            user_id=result.get("user_id"),
            created_at=result.get("created_at"),
            updated_at=result.get("updated_at")
        )
        
    except Exception as e:
        print(f"❌ [CATEGORIES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar categoría: {str(e)}"
        )


@router.delete("/{category_id}")
async def delete_category(
    category_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Eliminar una categoría personalizada"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"📁 [CATEGORIES] Eliminando categoría {category_id} para: {user_email}")
    
    supabase = get_supabase_client()
    
    # Verificar que la categoría existe
    check = supabase.table("categories").select("*").eq("id", category_id).execute()
    
    if not check.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Categoría no encontrada"
        )
    
    category_data = check.data[0]
    
    # No permitir eliminar categorías por defecto
    if category_data.get("is_default", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No se pueden eliminar las categorías por defecto"
        )
    
    # Verificar que pertenece al usuario
    if category_data.get("user_id") != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para eliminar esta categoría"
        )
    
    try:
        supabase_admin = get_supabase_admin()
        supabase_admin.table("categories").delete().eq("id", category_id).execute()
        
        print(f"✅ [CATEGORIES] Categoría eliminada: {category_id}")
        
        return {"message": "Categoría eliminada correctamente"}
        
    except Exception as e:
        print(f"❌ [CATEGORIES] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar categoría: {str(e)}"
        )


@router.post("/ensure-default")
async def ensure_default_categories_endpoint():
    """Endpoint para asegurar que las categorías por defecto existan"""
    
    print(f"📁 [CATEGORIES] Ejecutando asegurar categorías por defecto")
    
    await ensure_default_categories()
    
    return {"message": "Categorías por defecto aseguradas"}