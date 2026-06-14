# backend/app/auth.py
import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 días

# Configuración de seguridad
PASSWORD_HISTORY_LIMIT = 5

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Clientes Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verificar si la contraseña es correcta"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generar hash de la contraseña"""
    return pwd_context.hash(password)


def decode_access_token(token: str) -> Optional[dict]:
    """Decodificar token JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Crear token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ============================================
# FUNCIONES PARA HISTORIAL DE CONTRASEÑAS
# ============================================

async def add_password_to_history(user_id: str, password_hash: str) -> bool:
    """Agregar contraseña al historial"""
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        supabase.table("password_history").insert({
            "user_id": user_id,
            "password_hash": password_hash,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Mantener solo las últimas PASSWORD_HISTORY_LIMIT contraseñas
        response = supabase.table("password_history")\
            .select("id")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .execute()
        
        if response.data and len(response.data) > PASSWORD_HISTORY_LIMIT:
            ids_to_delete = [item["id"] for item in response.data[PASSWORD_HISTORY_LIMIT:]]
            for record_id in ids_to_delete:
                supabase.table("password_history").delete().eq("id", record_id).execute()
        
        print(f"✅ [PASSWORD_HISTORY] Contraseña agregada para usuario {user_id}")
        return True
    except Exception as e:
        print(f"⚠️ [PASSWORD_HISTORY] Error al agregar: {str(e)}")
        return False


async def check_password_reused(user_id: str, new_password: str) -> bool:
    """Verificar si la contraseña ya ha sido usada antes"""
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        response = supabase.table("password_history")\
            .select("password_hash")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(PASSWORD_HISTORY_LIMIT)\
            .execute()
        
        if not response.data:
            return False
        
        for record in response.data:
            if verify_password(new_password, record["password_hash"]):
                print(f"⚠️ [PASSWORD_HISTORY] Usuario {user_id} intentó reutilizar una contraseña antigua")
                return True
        
        return False
    except Exception as e:
        print(f"⚠️ [PASSWORD_HISTORY] Error al verificar: {str(e)}")
        return False


async def revoke_all_user_sessions(user_id: str, current_token: str = None) -> int:
    """Revocar todas las sesiones activas de un usuario"""
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        count_response = supabase.table("user_sessions")\
            .select("id", count="exact")\
            .eq("user_id", user_id)\
            .execute()
        
        total_sessions = count_response.count if hasattr(count_response, 'count') else 0
        
        if current_token:
            supabase.table("user_sessions").delete()\
                .eq("user_id", user_id)\
                .neq("session_token", current_token)\
                .execute()
            deleted_count = total_sessions - 1
        else:
            supabase.table("user_sessions").delete().eq("user_id", user_id).execute()
            deleted_count = total_sessions
        
        print(f"✅ [SESSION_REVOKE] Se cerraron {deleted_count} sesiones del usuario {user_id}")
        return deleted_count
    except Exception as e:
        print(f"⚠️ [SESSION_REVOKE] Error: {str(e)}")
        return 0