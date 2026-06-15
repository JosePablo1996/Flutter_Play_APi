# backend/app/routers/auth.py
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from supabase import create_client
import os
import httpx
import random
import secrets
from dotenv import load_dotenv
from ..models import UserRegister, UserLogin, TokenResponse, UserResponse
from ..auth import create_access_token, decode_access_token, get_password_hash
from ..services.email_service import EmailService
from ..services.device_alert import send_new_device_alert

# Cargar variables de entorno
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# Configuración de seguridad
PASSWORD_HISTORY_LIMIT = 5

router = APIRouter(prefix="/auth", tags=["Autenticación"])
security = HTTPBearer()

# Diccionario temporal para almacenar OTPs
otp_storage = {}

# Diccionario temporal para almacenar tokens de 2FA
two_factor_tokens = {}


# ============================================
# FUNCIONES AUXILIARES PARA DETECCIÓN DE DISPOSITIVO
# ============================================

def get_device_type(user_agent: str) -> str:
    """Detectar tipo de dispositivo desde el User-Agent"""
    ua = user_agent.lower()
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        return 'Mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        return 'Tablet'
    elif 'mac' in ua or 'windows' in ua or 'linux' in ua:
        return 'Desktop'
    return 'Unknown'

def get_browser(user_agent: str) -> str:
    """Detectar navegador desde el User-Agent"""
    ua = user_agent.lower()
    if 'chrome' in ua and 'edg' not in ua and 'opr' not in ua:
        return 'Chrome'
    elif 'firefox' in ua:
        return 'Firefox'
    elif 'safari' in ua and 'chrome' not in ua:
        return 'Safari'
    elif 'edg' in ua:
        return 'Edge'
    elif 'opr' in ua or 'opera' in ua:
        return 'Opera'
    return 'Unknown'

def get_os(user_agent: str) -> str:
    """Detectar sistema operativo desde el User-Agent"""
    ua = user_agent.lower()
    if 'windows' in ua:
        return 'Windows'
    elif 'mac' in ua:
        return 'macOS'
    elif 'linux' in ua:
        return 'Linux'
    elif 'android' in ua:
        return 'Android'
    elif 'ios' in ua or 'iphone' in ua or 'ipad' in ua:
        return 'iOS'
    return 'Unknown'

def get_client_ip(request: Request) -> str:
    """Obtener IP del cliente considerando proxies"""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"

def get_client_info(request: Request) -> dict:
    """Extraer información completa del cliente"""
    user_agent = request.headers.get("user-agent", "")
    
    return {
        "device_type": get_device_type(user_agent),
        "browser": get_browser(user_agent),
        "os": get_os(user_agent),
        "ip_address": get_client_ip(request),
        "user_agent": user_agent,
        "device_name": f"{get_device_type(user_agent)} - {get_os(user_agent)} ({get_browser(user_agent)})",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


# ============================================
# FUNCIONES DE REGISTRO DE HISTORIAL
# ============================================

async def log_activity(
    user_id: str, 
    action: str, 
    details: dict = None, 
    ip_address: str = None, 
    user_agent: str = None,
    location: str = None,
    status: str = "success"
):
    """Registrar actividad del usuario"""
    try:
        from ..database import get_supabase_admin
        supabase_admin = get_supabase_admin()
        
        activity_data = {
            "user_id": user_id,
            "action": action,
            "details": details or {},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "location": location or "Ubicación desconocida",
            "status": status,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_admin.table("activity_log").insert(activity_data).execute()
        print(f"✅ [ACTIVITY] Registrada: {action} para {user_id}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [ACTIVITY] Error: {str(e)}")
        return None


async def log_login_history(
    user_id: str, 
    email: str, 
    login_type: str, 
    ip_address: str = None, 
    user_agent: str = None,
    device_info: dict = None,
    location: str = None,
    status: str = "success"
):
    """Registrar historial de inicio de sesión"""
    try:
        from ..database import get_supabase_admin
        supabase_admin = get_supabase_admin()
        
        login_data = {
            "user_id": user_id,
            "email": email,
            "login_type": login_type,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "device_name": device_info.get("device_name") if device_info else None,
            "device_type": device_info.get("device_type") if device_info else None,
            "browser": device_info.get("browser") if device_info else None,
            "os": device_info.get("os") if device_info else None,
            "location": location or "Ubicación desconocida",
            "status": status,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_admin.table("login_history").insert(login_data).execute()
        print(f"✅ [LOGIN_HISTORY] Registrado: {login_type} para {email}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [LOGIN_HISTORY] Error: {str(e)}")
        return None


async def log_security_change(
    user_id: str,
    change_type: str,
    old_value: str = None,
    new_value: str = None,
    ip_address: str = None,
    user_agent: str = None,
    location: str = None,
    status: str = "success",
    details: dict = None
):
    """Registrar cambio de seguridad y enviar alerta por email"""
    try:
        from ..database import get_supabase_admin
        supabase_admin = get_supabase_admin()
        
        security_data = {
            "user_id": user_id,
            "change_type": change_type,
            "old_value": old_value,
            "new_value": new_value,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "location": location or "Ubicación desconocida",
            "status": status,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_admin.table("security_changes").insert(security_data).execute()
        print(f"✅ [SECURITY] Registrado: {change_type} para {user_id}")
        
        # Obtener email del usuario para enviar alerta
        user_response = supabase_admin.table("profiles").select("email").eq("id", user_id).execute()
        user_email = user_response.data[0]["email"] if user_response.data else None
        
        # Enviar alerta por email
        if user_email and status == "success":
            alert_details = {
                "change_type": change_type,
                "ip_address": ip_address or "Desconocida",
                "location": location or "Ubicación desconocida",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            if details:
                alert_details.update(details)
            
            alert_type = change_type
            if change_type == "password_change":
                alert_type = "password_change"
            elif change_type == "password_reset":
                alert_type = "password_change"
            
            await EmailService.send_security_alert_email(
                to_email=user_email,
                alert_type=alert_type,
                details=alert_details,
                name=user_id[:8]
            )
        
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [SECURITY] Error: {str(e)}")
        return None


async def create_user_session(request: Request, user_id: str, email: str, session_token: str = None) -> dict:
    """Crear una nueva sesión de usuario en user_sessions"""
    try:
        from ..database import get_supabase_admin
        supabase_admin = get_supabase_admin()
        
        client_info = get_client_info(request)
        
        if not session_token:
            session_token = secrets.token_urlsafe(64)
        
        # Primero, eliminar sesiones existentes con el mismo token (evitar duplicados)
        try:
            supabase_admin.table("user_sessions").delete().eq("session_token", session_token).execute()
        except Exception as e:
            print(f"⚠️ [CREATE_SESSION] Error limpiando token duplicado: {str(e)}")
        
        # Marcar otras sesiones como no actuales
        try:
            supabase_admin.table("user_sessions").update({"is_current": False}).eq("user_id", user_id).execute()
            print(f"✅ [CREATE_SESSION] Sesiones anteriores marcadas como no actuales")
        except Exception as e:
            print(f"⚠️ [CREATE_SESSION] Error actualizando otras sesiones: {str(e)}")
        
        session_data = {
            "user_id": user_id,
            "email": email,
            "session_token": session_token,
            "ip_address": client_info["ip_address"],
            "user_agent": client_info["user_agent"],
            "device_name": client_info["device_name"],
            "device_type": client_info["device_type"],
            "browser": client_info["browser"],
            "os": client_info["os"],
            "location": "Ubicación desconocida",
            "is_current": True,
            "last_activity": datetime.utcnow().isoformat(),
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
        }
        
        result = supabase_admin.table("user_sessions").insert(session_data).execute()
        print(f"✅ [CREATE_SESSION] Sesión creada para {email}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"❌ [CREATE_SESSION] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


# ============================================
# FUNCIONES DE SEGURIDAD ADICIONALES
# ============================================

async def add_password_to_history(user_id: str, password_hash: str) -> bool:
    """Agregar contraseña al historial"""
    try:
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        supabase_admin.table("password_history").insert({
            "user_id": user_id,
            "password_hash": password_hash,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        response = supabase_admin.table("password_history")\
            .select("id")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .execute()
        
        if response.data and len(response.data) > PASSWORD_HISTORY_LIMIT:
            ids_to_delete = [item["id"] for item in response.data[PASSWORD_HISTORY_LIMIT:]]
            for record_id in ids_to_delete:
                supabase_admin.table("password_history").delete().eq("id", record_id).execute()
        
        print(f"✅ [PASSWORD_HISTORY] Contraseña agregada para usuario {user_id}")
        return True
    except Exception as e:
        print(f"⚠️ [PASSWORD_HISTORY] Error al agregar: {str(e)}")
        return False


async def check_password_reused(user_id: str, new_password: str) -> bool:
    """Verificar si la contraseña ya ha sido usada antes"""
    try:
        from ..auth import verify_password
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        response = supabase_admin.table("password_history")\
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
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        count_response = supabase_admin.table("user_sessions")\
            .select("id", count="exact")\
            .eq("user_id", user_id)\
            .execute()
        
        total_sessions = count_response.count if hasattr(count_response, 'count') else 0
        
        if current_token:
            supabase_admin.table("user_sessions").delete()\
                .eq("user_id", user_id)\
                .neq("session_token", current_token)\
                .execute()
            deleted_count = total_sessions - 1
        else:
            supabase_admin.table("user_sessions").delete().eq("user_id", user_id).execute()
            deleted_count = total_sessions
        
        print(f"✅ [SESSION_REVOKE] Se cerraron {deleted_count} sesiones del usuario {user_id}")
        return deleted_count
    except Exception as e:
        print(f"⚠️ [SESSION_REVOKE] Error: {str(e)}")
        return 0


# ============================================
# OBTENER USUARIO ACTUAL
# ============================================

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Obtener usuario actual desde el token"""
    token = credentials.credentials
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# ============================================
# FUNCIÓN AUXILIAR PARA CONSTRUIR OBJETO USER
# ============================================

def build_user_response(profile_data: dict, user_id: str, email: str) -> dict:
    """Construir objeto de usuario para respuestas de API"""
    return {
        "id": user_id,
        "email": email,
        "full_name": profile_data.get("full_name", email.split('@')[0]),
        "student_id": profile_data.get("student_id"),
        "university": profile_data.get("university"),
        "avatar_url": profile_data.get("avatar_url"),
        "banner_url": profile_data.get("banner_url"),
        "currency": profile_data.get("currency", "USD"),
        "monthly_budget": float(profile_data.get("monthly_budget", 1000)),
        "role": profile_data.get("role", "user"),
        "two_factor_enabled": profile_data.get("two_factor_enabled", False),
        "created_at": profile_data.get("created_at"),
        "updated_at": profile_data.get("updated_at")
    }


# ============================================
# REGISTRO DE USUARIO
# ============================================

@router.post("/register", response_model=TokenResponse)
async def register(request: Request, user_data: UserRegister):
    """Registrar nuevo usuario"""
    
    print(f"📝 [REGISTER] Intentando registrar: {user_data.email}")
    
    url = f"{SUPABASE_URL}/auth/v1/signup"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "email": user_data.email,
        "password": user_data.password,
        "data": {
            "full_name": user_data.full_name
        }
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)
        
        if response.status_code not in [200, 201]:
            print(f"❌ [REGISTER] Error: {response.text}")
            error_detail = "Error al registrar usuario"
            try:
                error_data = response.json()
                if "user already registered" in str(error_data).lower():
                    error_detail = "El email ya está registrado"
            except:
                pass
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_detail
            )
        
        result = response.json()
        user_id = result.get("user", {}).get("id")
        email = result.get("user", {}).get("email")
        print(f"✅ [REGISTER] Usuario creado. ID: {user_id}")
    
    # Crear perfil
    try:
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        profile_data = {
            "id": user_id,
            "email": email,
            "full_name": user_data.full_name,
            "student_id": user_data.student_id,
            "university": user_data.university,
            "role": "user",
            "two_factor_enabled": False,
            "two_factor_secret": None,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        supabase_admin.table("profiles").insert(profile_data).execute()
        print(f"✅ [REGISTER] Perfil creado con rol: user")
    except Exception as e:
        print(f"⚠️ [REGISTER] Error creando perfil: {str(e)}")
    
    # Crear token
    access_token = create_access_token(data={"sub": user_id, "email": email, "role": "user"})
    
    # Registrar actividad
    client_info = get_client_info(request)
    await log_activity(
        user_id=user_id,
        action="user_registered",
        details={"email": email, "full_name": user_data.full_name},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    # Agregar contraseña al historial
    password_hash = get_password_hash(user_data.password)
    await add_password_to_history(user_id, password_hash)
    
    # Crear sesión
    await create_user_session(request, user_id, email, access_token)
    
    print(f"✅ [REGISTER] Registro completado")
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user_id,
            email=email,
            full_name=user_data.full_name,
            student_id=user_data.student_id,
            university=user_data.university,
            role="user"
        )
    )


# ============================================
# INICIO DE SESIÓN TRADICIONAL
# ============================================

@router.post("/login")
async def login(request: Request, user_data: UserLogin):
    """Iniciar sesión con soporte para 2FA y crear sesión activa"""
    
    print(f"🔐 [LOGIN] Intentando login: {user_data.email}")
    
    client_info = get_client_info(request)
    
    url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "email": user_data.email,
        "password": user_data.password
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)
        
        if response.status_code != 200:
            print(f"❌ [LOGIN] Error HTTP: {response.status_code}")
            
            await log_login_history(
                user_id="unknown",
                email=user_data.email,
                login_type="password",
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                device_info=client_info,
                status="failed"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email o contraseña incorrectos"
            )
        
        result = response.json()
        user_id = result.get("user", {}).get("id")
        email = result.get("user", {}).get("email")
        
        print(f"✅ [LOGIN] Autenticación exitosa. User ID: {user_id}")
    
    # Obtener perfil
    profile = {}
    try:
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        profile_response = supabase_admin.table("profiles").select("*").eq("id", user_id).execute()
        
        if profile_response.data:
            profile = profile_response.data[0]
            print(f"✅ [LOGIN] Perfil encontrado. Rol: {profile.get('role', 'user')}")
        else:
            new_profile = {
                "id": user_id,
                "email": email,
                "full_name": user_data.email.split('@')[0],
                "role": "user",
                "two_factor_enabled": False,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            supabase_admin.table("profiles").insert(new_profile).execute()
            profile = new_profile
            print(f"✅ [LOGIN] Perfil creado con rol: user")
    except Exception as e:
        print(f"⚠️ [LOGIN] Error obteniendo perfil: {str(e)}")
    
    # OBTENER EL ROL DEL PERFIL
    user_role = profile.get("role", "user")
    print(f"🔐 [LOGIN] Rol del usuario: {user_role}")
    
    # FUNCIÓN PARA CONSTRUIR EL OBJETO USER
    def build_user_object():
        return {
            "id": user_id,
            "email": email,
            "full_name": profile.get("full_name", email.split('@')[0]),
            "avatar_url": profile.get("avatar_url"),
            "banner_url": profile.get("banner_url"),
            "currency": profile.get("currency", "USD"),
            "monthly_budget": float(profile.get("monthly_budget", 1000)),
            "role": user_role
        }
    
    # VERIFICAR 2FA
    if profile.get("two_factor_enabled", False):
        secret = profile.get("two_factor_secret")
        if secret:
            temp_token = secrets.token_urlsafe(32)
            two_factor_tokens[temp_token] = {
                "secret": secret,
                "user_id": user_id,
                "email": email,
                "expires_at": datetime.utcnow() + timedelta(minutes=5),
                "attempts": 0
            }
            
            print(f"✅ [LOGIN] Usuario requiere 2FA - Token temporal generado")
            
            await log_login_history(
                user_id=user_id,
                email=email,
                login_type="2fa_pending",
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                device_info=client_info,
                status="pending"
            )
            
            user_obj = build_user_object()
            
            # Devolver TokenResponse correctamente formado
            return TokenResponse(
                access_token=None,
                token_type="bearer",
                requires_2fa=True,
                temp_token=temp_token,
                message="Se requiere autenticación de dos factores",
                user=UserResponse(
                    id=user_id,
                    email=email,
                    full_name=profile.get("full_name"),
                    avatar_url=profile.get("avatar_url"),
                    role=user_role
                )
            )
    
    # Login exitoso sin 2FA
    access_token = create_access_token(data={"sub": user_id, "email": email, "role": user_role})
    print(f"✅ [LOGIN] Access token generado con rol: {user_role}")
    
    # Crear sesión
    await create_user_session(request, user_id, email, access_token)
    
    # ALERTA PARA NUEVO DISPOSITIVO
    try:
        await send_new_device_alert(user_id, client_info, request)
        print(f"✅ [LOGIN] Alerta de nuevo dispositivo verificada")
    except Exception as e:
        print(f"⚠️ [LOGIN] Error enviando alerta de dispositivo: {str(e)}")
    
    # Registrar login exitoso
    await log_login_history(
        user_id=user_id,
        email=email,
        login_type="password",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        device_info=client_info,
        status="success"
    )
    
    await log_activity(
        user_id=user_id,
        action="login",
        details={"login_type": "password", "device": client_info["device_name"]},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    print(f"✅ [LOGIN] Login completado para: {email}")
    
    user_obj = build_user_object()
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user_id,
            email=email,
            full_name=profile.get("full_name"),
            student_id=profile.get("student_id"),
            university=profile.get("university"),
            avatar_url=profile.get("avatar_url"),
            banner_url=profile.get("banner_url"),
            currency=profile.get("currency", "USD"),
            monthly_budget=float(profile.get("monthly_budget", 1000)),
            role=user_role
        )
    )


# ============================================
# LOGIN CON OTP (SIN CONTRASEÑA)
# ============================================

@router.post("/login-otp-request")
async def login_otp_request(request: Request, email: str):
    """Solicitar código OTP para login sin contraseña"""
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    client_info = get_client_info(request)
    
    print(f"📧 [LOGIN-OTP] Solicitando código para: {email}")
    
    user = supabase.table("profiles").select("id, email, full_name, avatar_url, role").eq("email", email).execute()
    
    if not user.data:
        print(f"⚠️ [LOGIN-OTP] Email no registrado: {email}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El email no está registrado en el sistema"
        )
    
    user_data = user.data[0]
    user_id = user_data["id"]
    user_name = user_data.get("full_name", "usuario")
    user_avatar = user_data.get("avatar_url")
    user_role = user_data.get("role", "user")
    
    otp_code = str(random.randint(100000, 999999))
    
    otp_storage[f"login_{email}"] = {
        "code": otp_code,
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "user_id": user_id,
        "attempts": 0,
        "purpose": "login"
    }
    
    email_sent = await EmailService.send_login_otp_email(email, otp_code, user_name)
    
    if email_sent:
        await log_activity(
            user_id=user_id,
            action="otp_requested",
            details={"login_type": "otp"},
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        
        return {
            "message": "Código OTP enviado a tu correo electrónico",
            "user": {
                "id": user_id,
                "email": email,
                "full_name": user_name,
                "avatar_url": user_avatar,
                "role": user_role
            }
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al enviar el código OTP"
        )


# ============================================
# LOGIN WITH OTP (CORREGIDO - VERSIÓN FINAL)
# ============================================

@router.post("/login-with-otp", response_model=TokenResponse)
async def login_with_otp(request: Request, email: str, otp_code: str):
    """Iniciar sesión con código OTP (soporta 2FA correctamente)"""
    
    client_info = get_client_info(request)
    storage_key = f"login_{email}"
    
    if storage_key not in otp_storage:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código OTP no encontrado o expirado"
        )
    
    otp_data = otp_storage[storage_key]
    
    if datetime.utcnow() > otp_data["expires_at"]:
        del otp_storage[storage_key]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El código OTP ha expirado"
        )
    
    if otp_data["attempts"] >= 5:
        del otp_storage[storage_key]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Demasiados intentos fallidos"
        )
    
    if otp_data["code"] != otp_code:
        otp_data["attempts"] += 1
        remaining_attempts = 5 - otp_data["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Código incorrecto. Te quedan {remaining_attempts} intentos"
        )
    
    user_id = otp_data["user_id"]
    del otp_storage[storage_key]
    
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    profile_response = supabase.table("profiles").select("*").eq("id", user_id).execute()
    profile = profile_response.data[0] if profile_response.data else {}
    
    user_role = profile.get("role", "user")
    
    # ============================================
    # CASO 1: Usuario con 2FA activado
    # ============================================
    if profile.get("two_factor_enabled", False):
        secret = profile.get("two_factor_secret")
        if secret:
            temp_token = secrets.token_urlsafe(32)
            two_factor_tokens[temp_token] = {
                "secret": secret,
                "user_id": user_id,
                "email": email,
                "expires_at": datetime.utcnow() + timedelta(minutes=5),
                "attempts": 0
            }
            
            print(f"✅ [LOGIN-OTP] Usuario requiere 2FA - Token temporal generado")
            
            # Registrar intento de 2FA pendiente
            await log_login_history(
                user_id=user_id,
                email=email,
                login_type="otp_2fa_pending",
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                device_info=client_info,
                status="pending"
            )
            
            # ✅ CORRECCIÓN: Devolver TokenResponse en lugar de dict
            return TokenResponse(
                access_token=None,
                token_type="bearer",
                requires_2fa=True,
                temp_token=temp_token,
                message="Se requiere autenticación de dos factores",
                user=UserResponse(
                    id=user_id,
                    email=email,
                    full_name=profile.get("full_name", email.split('@')[0]),
                    avatar_url=profile.get("avatar_url"),
                    role=user_role
                )
            )
    
    # ============================================
    # CASO 2: Usuario sin 2FA (flujo normal)
    # ============================================
    access_token = create_access_token(data={"sub": user_id, "email": email, "role": user_role})
    
    await create_user_session(request, user_id, email, access_token)
    
    # ALERTA PARA NUEVO DISPOSITIVO
    try:
        await send_new_device_alert(user_id, client_info, request)
        print(f"✅ [LOGIN-OTP] Alerta de nuevo dispositivo verificada")
    except Exception as e:
        print(f"⚠️ [LOGIN-OTP] Error enviando alerta de dispositivo: {str(e)}")
    
    await log_login_history(
        user_id=user_id,
        email=email,
        login_type="otp",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        device_info=client_info,
        status="success"
    )
    
    await log_activity(
        user_id=user_id,
        action="login",
        details={"login_type": "otp", "device": client_info["device_name"]},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    print(f"✅ [LOGIN-OTP] Login exitoso para: {email}")
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user_id,
            email=email,
            full_name=profile.get("full_name"),
            student_id=profile.get("student_id"),
            university=profile.get("university"),
            avatar_url=profile.get("avatar_url"),
            banner_url=profile.get("banner_url"),
            currency=profile.get("currency", "USD"),
            monthly_budget=float(profile.get("monthly_budget", 1000)),
            role=user_role
        )
    )


# ============================================
# OBTENER USUARIO ACTUAL
# ============================================

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Obtener información del usuario actual"""
    
    print(f"👤 [ME] Obteniendo perfil")
    print(f"👤 [ME] Payload recibido: {current_user}")
    
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de conexión"
        )
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"👤 [ME] user_id: {user_id}")
    print(f"👤 [ME] email desde token: {email}")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido: no user_id"
        )
    
    # Buscar el perfil por ID
    response = supabase.table("profiles").select("*").eq("id", user_id).execute()
    
    if not response.data:
        # Crear perfil si no existe
        profile_data = {
            "id": user_id,
            "email": email,
            "role": "user",
            "two_factor_enabled": False,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        try:
            supabase_admin.table("profiles").insert(profile_data).execute()
            profile = profile_data
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al crear perfil: {str(e)}"
            )
    else:
        profile = response.data[0]
    
    user_role = profile.get("role", "user")
    print(f"👤 [ME] Rol del usuario: {user_role}")
    
    if not profile.get("email") and email:
        profile["email"] = email
    
    if not profile.get("email"):
        print(f"❌ [ME] Error: email es None para usuario {user_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email no disponible para este usuario"
        )
    
    print(f"✅ [ME] Perfil obtenido para: {profile.get('email')}")
    
    return UserResponse(
        id=user_id,
        email=profile.get("email"),
        full_name=profile.get("full_name"),
        student_id=profile.get("student_id"),
        university=profile.get("university"),
        avatar_url=profile.get("avatar_url"),
        banner_url=profile.get("banner_url"),
        currency=profile.get("currency", "USD"),
        monthly_budget=float(profile.get("monthly_budget", 1000)),
        role=user_role
    )


# ============================================
# VERIFICAR TOKEN TEMPORAL 2FA
# ============================================

@router.post("/verify-2fa-token")
async def verify_2fa_token(temp_token: str):
    """Verificar token temporal de 2FA"""
    
    if temp_token not in two_factor_tokens:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido o expirado"
        )
    
    token_data = two_factor_tokens[temp_token]
    
    if datetime.utcnow() > token_data["expires_at"]:
        del two_factor_tokens[temp_token]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token expirado"
        )
    
    return {"valid": True}


# ============================================
# RECUPERACIÓN DE CONTRASEÑA CON OTP
# ============================================

@router.post("/request-otp")
async def request_otp(request: Request, email: str):
    """Solicitar código OTP para recuperación de contraseña"""
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    client_info = get_client_info(request)
    
    user = supabase.table("profiles").select("id, email, full_name").eq("email", email).execute()
    
    if not user.data:
        return {"message": "Si el email está registrado, recibirás un código OTP"}
    
    user_data = user.data[0]
    user_id = user_data["id"]
    user_name = user_data.get("full_name", "usuario")
    
    otp_code = str(random.randint(100000, 999999))
    
    otp_storage[email] = {
        "code": otp_code,
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "user_id": user_id,
        "attempts": 0
    }
    
    email_sent = await EmailService.send_otp_email(email, otp_code, user_name)
    
    if email_sent:
        await log_activity(
            user_id=user_id,
            action="password_reset_requested",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        return {"message": "Código OTP enviado a tu correo electrónico"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al enviar el código OTP"
        )


@router.post("/verify-otp")
async def verify_otp(request: Request, email: str, otp_code: str):
    """Verificar código OTP para recuperación"""
    client_info = get_client_info(request)
    
    if email not in otp_storage:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código OTP no encontrado"
        )
    
    otp_data = otp_storage[email]
    
    if datetime.utcnow() > otp_data["expires_at"]:
        del otp_storage[email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código expirado"
        )
    
    if otp_data["attempts"] >= 5:
        del otp_storage[email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Demasiados intentos"
        )
    
    if otp_data["code"] != otp_code:
        otp_data["attempts"] += 1
        remaining_attempts = 5 - otp_data["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Código incorrecto. Te quedan {remaining_attempts} intentos"
        )
    
    reset_token = create_access_token(
        data={"sub": otp_data["user_id"], "email": email, "purpose": "password_reset"},
        expires_delta=timedelta(minutes=15)
    )
    
    del otp_storage[email]
    
    await log_activity(
        user_id=otp_data["user_id"],
        action="password_reset_verified",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    return {
        "message": "Código verificado",
        "reset_token": reset_token
    }


@router.post("/reset-password-with-otp")
async def reset_password_with_otp(request: Request, reset_token: str, new_password: str):
    """Restablecer contraseña con OTP verificado"""
    from ..auth import get_password_hash
    client_info = get_client_info(request)
    
    payload = decode_access_token(reset_token)
    if not payload or payload.get("purpose") != "password_reset":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    
    user_id = payload.get("sub")
    email = payload.get("email")
    
    # Validar fortaleza de la contraseña
    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe tener al menos 8 caracteres"
        )
    
    # Verificar que no reutilice contraseña antigua
    is_reused = await check_password_reused(user_id, new_password)
    if is_reused:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puedes reutilizar una contraseña que hayas usado anteriormente"
        )
    
    supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    
    try:
        supabase_admin.auth.admin.update_user_by_id(
            user_id,
            {"password": new_password}
        )
        
        # Agregar nueva contraseña al historial
        new_password_hash = get_password_hash(new_password)
        await add_password_to_history(user_id, new_password_hash)
        
        # Cerrar todas las sesiones activas
        sessions_revoked = await revoke_all_user_sessions(user_id, current_token=None)
        
        await log_security_change(
            user_id=user_id,
            change_type="password_reset",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            status="success",
            details={"sessions_revoked": sessions_revoked}
        )
        
        await log_activity(
            user_id=user_id,
            action="password_reset_completed",
            details={"sessions_revoked": sessions_revoked},
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        
        return {
            "message": f"Contraseña actualizada. Se cerraron {sessions_revoked} sesiones activas.",
            "requires_relogin": True
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error al actualizar la contraseña"
        )


# ============================================
# RECUPERAR CONTRASEÑA (FORGOT PASSWORD - SUPABASE)
# ============================================

@router.post("/forgot-password")
async def forgot_password(request: Request, email: str):
    """Enviar correo de recuperación de contraseña usando Supabase"""
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    
    try:
        supabase.auth.reset_password_for_email(email)
        return {"message": "Si el email está registrado, recibirás un enlace de recuperación"}
    except Exception as e:
        return {"message": "Si el email está registrado, recibirás un enlace de recuperación"}


@router.post("/reset-password")
async def reset_password(request: Request, token: str, new_password: str):
    """Restablecer contraseña con token de Supabase"""
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    
    try:
        supabase.auth.update_user(
            password=new_password,
            access_token=token
        )
        return {"message": "Contraseña actualizada"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido o expirado"
        )


# ============================================
# CAMBIAR CONTRASEÑA (USUARIO AUTENTICADO)
# ============================================

@router.post("/change-password")
async def change_password(
    request: Request,
    current_password: str,
    new_password: str,
    current_user: dict = Depends(get_current_user)
):
    """Cambiar contraseña del usuario autenticado con validaciones de seguridad"""
    
    from ..auth import get_password_hash
    
    supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    user_id = current_user.get("sub")
    email = current_user.get("email")
    client_info = get_client_info(request)
    
    # Verificar contraseña actual mediante login
    try:
        supabase.auth.sign_in_with_password({
            "email": email,
            "password": current_password
        })
        print(f"✅ [CHANGE_PASSWORD] Contraseña actual verificada")
    except Exception as e:
        await log_security_change(
            user_id=user_id,
            change_type="password_change",
            status="failed",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña actual incorrecta"
        )
    
    # Validar que la nueva contraseña sea diferente a la actual
    if current_password == new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La nueva contraseña debe ser diferente a la actual"
        )
    
    # Validar fortaleza de la contraseña
    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe tener al menos 8 caracteres"
        )
    
    # Validar que la nueva contraseña no haya sido usada antes
    is_reused = await check_password_reused(user_id, new_password)
    if is_reused:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No puedes reutilizar una contraseña que hayas usado anteriormente. El sistema recuerda las últimas {PASSWORD_HISTORY_LIMIT} contraseñas."
        )
    
    # Actualizar contraseña en Supabase Auth
    try:
        supabase_admin.auth.admin.update_user_by_id(
            user_id,
            {"password": new_password}
        )
        print(f"✅ [CHANGE_PASSWORD] Contraseña actualizada en Auth")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al actualizar la contraseña: {str(e)}"
        )
    
    # Agregar nueva contraseña al historial
    new_password_hash = get_password_hash(new_password)
    await add_password_to_history(user_id, new_password_hash)
    
    # Obtener el token actual antes de cerrar sesiones
    auth_header = request.headers.get("authorization", "")
    current_token = None
    if auth_header.startswith("Bearer "):
        current_token = auth_header.replace("Bearer ", "")
    
    # CERRAR TODAS LAS SESIONES ACTIVAS (incluyendo la actual)
    sessions_revoked = await revoke_all_user_sessions(user_id, current_token=None)
    
    # Registrar el cambio de seguridad exitoso
    await log_security_change(
        user_id=user_id,
        change_type="password_change",
        status="success",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={"sessions_revoked": sessions_revoked}
    )
    
    await log_activity(
        user_id=user_id,
        action="password_changed",
        details={"sessions_revoked": sessions_revoked},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    print(f"✅ [CHANGE_PASSWORD] Contraseña actualizada para {email}. Se cerraron {sessions_revoked} sesiones.")
    
    return {
        "message": f"Contraseña actualizada correctamente. Se han cerrado {sessions_revoked} sesiones activas por seguridad. Por favor, inicia sesión nuevamente.",
        "requires_relogin": True,
        "sessions_revoked": sessions_revoked
    }


# ============================================
# CERRAR SESIÓN
# ============================================

@router.post("/logout")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    """Cerrar sesión"""
    user_id = current_user.get("sub")
    email = current_user.get("email")
    client_info = get_client_info(request)
    
    # Opcional: Eliminar la sesión actual de la base de datos
    try:
        auth_header = request.headers.get("authorization", "")
        current_token = None
        if auth_header.startswith("Bearer "):
            current_token = auth_header.replace("Bearer ", "")
        
        if current_token:
            supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
            supabase_admin.table("user_sessions").delete().eq("session_token", current_token).execute()
    except Exception as e:
        print(f"⚠️ [LOGOUT] Error eliminando sesión: {str(e)}")
    
    await log_activity(
        user_id=user_id,
        action="logout",
        details={"device": client_info["device_name"]},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    print(f"🚪 [LOGOUT] Cerrando sesión: {email}")
    return {"message": "Sesión cerrada correctamente"}