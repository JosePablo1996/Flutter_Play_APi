# backend/app/routers/profile.py
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import os

from ..auth_utils import get_current_user
from ..database import get_supabase_client, get_supabase_admin

router = APIRouter(prefix="/profile", tags=["Perfil"])

# ============================================
# MODELOS DE DATOS
# ============================================

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    student_id: Optional[str] = None
    university: Optional[str] = None
    currency: Optional[str] = None
    monthly_budget: Optional[float] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    biometric_enabled: Optional[bool] = None
    notifications_enabled: Optional[bool] = None

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    student_id: Optional[str] = None
    university: Optional[str] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    currency: str = "USD"
    monthly_budget: float = 1000
    role: str = "user"  # 👈 NUEVO: rol del usuario
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# ============================================
# ENDPOINTS
# ============================================

@router.get("/", response_model=UserResponse)
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Obtener perfil del usuario actual"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"👤 [PROFILE] Obteniendo perfil para: {user_email}")
    
    supabase = get_supabase_client()
    response = supabase.table("profiles").select("*").eq("id", user_id).execute()
    
    if not response.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado"
        )
    
    profile = response.data[0]
    
    print(f"✅ [PROFILE] Perfil obtenido - Rol: {profile.get('role', 'user')}")
    
    return UserResponse(
        id=profile.get("id"),
        email=profile.get("email"),
        full_name=profile.get("full_name"),
        student_id=profile.get("student_id"),
        university=profile.get("university"),
        avatar_url=profile.get("avatar_url"),
        banner_url=profile.get("banner_url"),
        currency=profile.get("currency", "USD"),
        monthly_budget=float(profile.get("monthly_budget", 1000)),
        role=profile.get("role", "user"),  # 👈 NUEVO: incluir el rol
        created_at=profile.get("created_at"),
        updated_at=profile.get("updated_at")
    )


@router.put("/", response_model=UserResponse)
async def update_profile(
    profile_data: ProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar perfil del usuario actual"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"👤 [PROFILE] Actualizando perfil para: {user_email}")
    
    # Preparar datos para actualizar (solo campos proporcionados)
    update_data = profile_data.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow().isoformat()
    
    # No permitir cambiar el rol desde este endpoint (solo admin puede hacerlo)
    if "role" in update_data:
        del update_data["role"]
    
    try:
        supabase_admin = get_supabase_admin()
        response = supabase_admin.table("profiles").update(update_data).eq("id", user_id).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al actualizar el perfil"
            )
        
        profile = response.data[0]
        
        print(f"✅ [PROFILE] Perfil actualizado para: {user_email}")
        
        return UserResponse(
            id=profile.get("id"),
            email=profile.get("email"),
            full_name=profile.get("full_name"),
            student_id=profile.get("student_id"),
            university=profile.get("university"),
            avatar_url=profile.get("avatar_url"),
            banner_url=profile.get("banner_url"),
            currency=profile.get("currency", "USD"),
            monthly_budget=float(profile.get("monthly_budget", 1000)),
            role=profile.get("role", "user"),  # 👈 NUEVO: incluir el rol
            created_at=profile.get("created_at"),
            updated_at=profile.get("updated_at")
        )
        
    except Exception as e:
        print(f"❌ [PROFILE] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar perfil: {str(e)}"
        )


@router.post("/avatar")
async def update_avatar(
    avatar_url: str,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar solo el avatar del usuario"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"👤 [PROFILE] Actualizando avatar para: {user_email}")
    
    try:
        supabase_admin = get_supabase_admin()
        response = supabase_admin.table("profiles").update({
            "avatar_url": avatar_url,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", user_id).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al actualizar el avatar"
            )
        
        print(f"✅ [PROFILE] Avatar actualizado para: {user_email}")
        
        return {"message": "Avatar actualizado correctamente", "avatar_url": avatar_url}
        
    except Exception as e:
        print(f"❌ [PROFILE] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar avatar: {str(e)}"
        )


@router.post("/banner")
async def update_banner(
    banner_url: str,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar solo el banner del usuario"""
    
    user_id = current_user.get("id")
    user_email = current_user.get("email")
    
    print(f"👤 [PROFILE] Actualizando banner para: {user_email}")
    
    try:
        supabase_admin = get_supabase_admin()
        response = supabase_admin.table("profiles").update({
            "banner_url": banner_url,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", user_id).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al actualizar el banner"
            )
        
        print(f"✅ [PROFILE] Banner actualizado para: {user_email}")
        
        return {"message": "Banner actualizado correctamente", "banner_url": banner_url}
        
    except Exception as e:
        print(f"❌ [PROFILE] Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar banner: {str(e)}"
        )


@router.get("/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    """Obtener todos los usuarios (solo para administradores)"""
    
    user_role = current_user.get("role", "user")
    
    # Verificar que el usuario sea administrador
    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado. Se requieren privilegios de administrador."
        )
    
    print(f"👑 [ADMIN] Obteniendo todos los usuarios")
    
    supabase = get_supabase_client()
    response = supabase.table("profiles").select("id, email, full_name, role, created_at").execute()
    
    return response.data


@router.put("/admin/role/{user_id}")
async def update_user_role(
    user_id: str,
    role: str,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar el rol de un usuario (solo para administradores)"""
    
    user_role = current_user.get("role", "user")
    
    # Verificar que el usuario sea administrador
    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado. Se requieren privilegios de administrador."
        )
    
    # Validar que el rol sea válido
    if role not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rol inválido. Los roles permitidos son: user, admin"
        )
    
    print(f"👑 [ADMIN] Actualizando rol del usuario {user_id} a {role}")
    
    supabase_admin = get_supabase_admin()
    response = supabase_admin.table("profiles").update({
        "role": role,
        "updated_at": datetime.utcnow().isoformat()
    }).eq("id", user_id).execute()
    
    if not response.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    return {"message": f"Rol actualizado a {role} correctamente", "user": response.data[0]}