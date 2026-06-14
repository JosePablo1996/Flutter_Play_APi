# backend/app/auth_utils.py
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"

security = HTTPBearer()

def decode_access_token(token: str):
    """Decodificar token JWT"""
    from jose import jwt
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        print(f"❌ [AUTH_UTILS] Error decodificando token: {e}")
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Obtiene el usuario actual desde el token JWT"""
    token = credentials.credentials
    
    print(f"🔐 [AUTH_UTILS] Verificando token...")
    print(f"🔐 [AUTH_UTILS] Token (primeros 50 chars): {token[:50]}...")
    
    # Decodificar token
    payload = decode_access_token(token)
    
    if not payload:
        print(f"❌ [AUTH_UTILS] Token inválido o expirado")
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    
    print(f"🔐 [AUTH_UTILS] Payload decodificado: {payload}")
    
    user_id = payload.get("sub")
    email_from_token = payload.get("email")  # Intentar obtener email del token
    
    if not user_id:
        print(f"❌ [AUTH_UTILS] Token inválido: no user_id")
        raise HTTPException(status_code=401, detail="Token inválido: no user_id")
    
    print(f"🔐 [AUTH_UTILS] User ID desde token: {user_id}")
    print(f"🔐 [AUTH_UTILS] Email desde token: {email_from_token}")
    
    # Obtener el usuario completo de la base de datos
    from app.database import get_supabase_client
    supabase = get_supabase_client()
    
    # Intentar buscar por email si está disponible, si no por ID
    if email_from_token:
        print(f"🔐 [AUTH_UTILS] Buscando usuario por email: {email_from_token}")
        result = supabase.table('profiles').select('*').eq('email', email_from_token).execute()
    else:
        print(f"🔐 [AUTH_UTILS] Buscando usuario por ID: {user_id}")
        result = supabase.table('profiles').select('*').eq('id', user_id).execute()
    
    if not result.data:
        print(f"❌ [AUTH_UTILS] Usuario no encontrado en BD")
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    user_data = result.data[0]
    
    print(f"✅ [AUTH_UTILS] Usuario autenticado: {user_data.get('email')}")
    print(f"✅ [AUTH_UTILS] Datos del usuario: id={user_data.get('id')}, email={user_data.get('email')}, full_name={user_data.get('full_name')}")
    
    # Devolver directamente el diccionario con los campos que espera UserResponse
    return {
        "id": user_data.get("id"),
        "email": user_data.get("email"),
        "full_name": user_data.get("full_name", ""),
        "student_id": user_data.get("student_id"),
        "university": user_data.get("university"),
        "avatar_url": user_data.get("avatar_url"),
        "banner_url": user_data.get("banner_url"),
        "currency": user_data.get("currency", "USD"),
        "monthly_budget": user_data.get("monthly_budget", 1000),
        "biometric_enabled": user_data.get("biometric_enabled", False),
        "notifications_enabled": user_data.get("notifications_enabled", True),
        "two_factor_enabled": user_data.get("two_factor_enabled", False),
        "created_at": user_data.get("created_at"),
        "updated_at": user_data.get("updated_at")
    }