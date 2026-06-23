# backend/app/routers/two_factor.py
from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timedelta
from pydantic import BaseModel
import pyotp
import qrcode
import base64
import secrets
import random
from io import BytesIO
from .auth import get_current_user, two_factor_tokens
from ..database import get_supabase_client, get_supabase_admin
from ..services.email_service import EmailService
from ..models import TokenResponse, UserResponse
import os
from supabase import create_client

router = APIRouter(prefix="/auth/2fa", tags=["2FA"])

# ============================================
# MODELOS
# ============================================

class Setup2FARequest(BaseModel):
    password: str

class Verify2FARequest(BaseModel):
    code: str
    secret: str

class VerifyLogin2FARequest(BaseModel):
    code: str
    temp_token: str

# Almacenamiento temporal para setup de 2FA
setup_tokens = {}


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def get_client_info(request: Request) -> dict:
    """Extraer información del cliente desde la request"""
    user_agent = request.headers.get("user-agent", "")
    ua = user_agent.lower()
    
    # Detectar tipo de dispositivo
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        device_type = "Mobile"
    elif 'tablet' in ua or 'ipad' in ua:
        device_type = "Tablet"
    elif 'mac' in ua or 'windows' in ua or 'linux' in ua:
        device_type = "Desktop"
    else:
        device_type = "Unknown"
    
    # Detectar navegador
    if 'chrome' in ua and 'edg' not in ua and 'opr' not in ua:
        browser = "Chrome"
    elif 'firefox' in ua:
        browser = "Firefox"
    elif 'safari' in ua and 'chrome' not in ua:
        browser = "Safari"
    elif 'edg' in ua:
        browser = "Edge"
    elif 'opr' in ua or 'opera' in ua:
        browser = "Opera"
    else:
        browser = "Unknown"
    
    # Detectar SO
    if 'windows' in ua:
        os_name = "Windows"
    elif 'mac' in ua:
        os_name = "macOS"
    elif 'linux' in ua:
        os_name = "Linux"
    elif 'android' in ua:
        os_name = "Android"
    elif 'ios' in ua or 'iphone' in ua or 'ipad' in ua:
        os_name = "iOS"
    else:
        os_name = "Unknown"
    
    # Obtener IP
    ip_address = request.headers.get("x-forwarded-for")
    if not ip_address:
        ip_address = request.headers.get("x-real-ip")
    if not ip_address and request.client:
        ip_address = request.client.host
    if ip_address and "," in ip_address:
        ip_address = ip_address.split(",")[0].strip()
    if not ip_address:
        ip_address = "Unknown"
    
    device_name = f"{device_type} - {os_name} ({browser})"
    
    return {
        "device_type": device_type,
        "browser": browser,
        "os": os_name,
        "ip_address": ip_address,
        "device_name": device_name,
        "user_agent": user_agent,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


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
        print(f"✅ [2FA-ACTIVITY] Registrada: {action} para {user_id}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [2FA-ACTIVITY] Error: {str(e)}")
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
        print(f"✅ [2FA-LOGIN_HISTORY] Registrado: {login_type} para {email}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [2FA-LOGIN_HISTORY] Error: {str(e)}")
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
        print(f"✅ [2FA-SECURITY] Registrado: {change_type} para {user_id}")
        
        # Obtener email del usuario para enviar alerta
        user_response = supabase_admin.table("profiles").select("email").eq("id", user_id).execute()
        user_email = user_response.data[0]["email"] if user_response.data else None
        
        # Enviar alerta por email si el cambio fue exitoso
        if user_email and status == "success":
            alert_details = {
                "change_type": change_type,
                "ip_address": ip_address or "Desconocida",
                "location": location or "Ubicación desconocida",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            if details:
                alert_details.update(details)
            
            await EmailService.send_security_alert_email(
                to_email=user_email,
                alert_type=change_type,
                details=alert_details,
                name=user_id[:8]
            )
        
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [2FA-SECURITY] Error: {str(e)}")
        return None


async def create_user_session(request: Request, user_id: str, email: str, session_token: str = None) -> dict:
    """Crear una nueva sesión de usuario en user_sessions"""
    try:
        supabase_admin = get_supabase_admin()
        
        client_info = get_client_info(request)
        
        if not session_token:
            session_token = secrets.token_urlsafe(64)
        
        # Primero, eliminar sesiones existentes con el mismo token (evitar duplicados)
        try:
            supabase_admin.table("user_sessions").delete().eq("session_token", session_token).execute()
        except Exception as e:
            print(f"⚠️ [2FA-CREATE_SESSION] Error limpiando token duplicado: {str(e)}")
        
        # Marcar otras sesiones como no actuales
        try:
            supabase_admin.table("user_sessions").update({"is_current": False}).eq("user_id", user_id).execute()
            print(f"✅ [2FA-CREATE_SESSION] Sesiones anteriores marcadas como no actuales")
        except Exception as e:
            print(f"⚠️ [2FA-CREATE_SESSION] Error actualizando otras sesiones: {str(e)}")
        
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
        print(f"✅ [2FA-CREATE_SESSION] Sesión creada para {email}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"❌ [2FA-CREATE_SESSION] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


# ============================================
# ENDPOINTS DE 2FA
# ============================================

@router.get("/status")
async def get_2fa_status(current_user: dict = Depends(get_current_user)):
    """Obtener estado de 2FA del usuario"""
    supabase = get_supabase_client()
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    response = supabase.table("profiles").select("two_factor_enabled").eq("id", user_id).execute()
    
    enabled = False
    if response.data:
        enabled = response.data[0].get("two_factor_enabled", False)
    
    print(f"🔐 [2FA-STATUS] Usuario {email} - 2FA activado: {enabled}")
    return {"enabled": enabled}


# ============================================
# ✅ ENDPOINT CORREGIDO: SETUP 2FA - VERSIÓN CON AUTH CLIENT
# ============================================

@router.post("/setup")
async def setup_2fa(
    request: Request,
    setup_data: Setup2FARequest,
    current_user: dict = Depends(get_current_user)
):
    """Generar secreto y QR para configurar 2FA"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"🔐 [2FA-SETUP] ==================== INICIO ====================")
    print(f"🔐 [2FA-SETUP] User ID: {user_id}")
    print(f"🔐 [2FA-SETUP] Email: {email}")
    print(f"🔐 [2FA-SETUP] Contraseña recibida: {'****' if setup_data.password else 'vacía'}")
    print(f"🔐 [2FA-SETUP] Longitud de contraseña: {len(setup_data.password) if setup_data.password else 0}")
    
    # ✅ OBTENER VARIABLES DE ENTORNO
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
    
    print(f"🔐 [2FA-SETUP] SUPABASE_URL: {SUPABASE_URL[:20] + '...' if SUPABASE_URL else 'NO DEFINIDA'}")
    print(f"🔐 [2FA-SETUP] SUPABASE_ANON_KEY: {SUPABASE_ANON_KEY[:15] + '...' if SUPABASE_ANON_KEY else 'NO DEFINIDA'}")
    
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        print(f"❌ [2FA-SETUP] Variables de entorno no configuradas")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Variables de entorno no configuradas"
        )
    
    # ✅ CREAR CLIENTE DE AUTENTICACIÓN
    try:
        # Usar el método POST directamente a la API REST de Supabase
        import httpx
        
        # URL para verificar contraseña usando la API REST de Supabase
        auth_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
        
        headers = {
            "apikey": SUPABASE_ANON_KEY,
            "Content-Type": "application/json"
        }
        
        data = {
            "email": email,
            "password": setup_data.password
        }
        
        print(f"🔐 [2FA-SETUP] Verificando contraseña con Supabase Auth API...")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(auth_url, headers=headers, json=data)
            
            if response.status_code != 200:
                print(f"❌ [2FA-SETUP] Contraseña incorrecta. Status: {response.status_code}")
                print(f"❌ [2FA-SETUP] Respuesta: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Contraseña incorrecta. Por favor, verifica tu contraseña."
                )
            
            auth_result = response.json()
            print(f"✅ [2FA-SETUP] Contraseña verificada correctamente para: {email}")
            print(f"✅ [2FA-SETUP] Usuario autenticado: {auth_result.get('user', {}).get('email', 'No user')}")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ [2FA-SETUP] Error verificando contraseña para: {email}")
        print(f"❌ [2FA-SETUP] Error detallado: {str(e)}")
        print(f"❌ [2FA-SETUP] Tipo de error: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Error al verificar la contraseña: {str(e)}"
        )
    
    # ✅ GENERAR SECRETO 2FA
    secret = pyotp.random_base32()
    
    # Crear URI para Google Authenticator
    issuer_name = "Flutter Play"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer_name)
    
    # Generar QR code
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convertir QR a base64
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    qr_code = f"data:image/png;base64,{qr_base64}"
    
    # Guardar secreto temporalmente
    setup_tokens[f"2fa_setup_{user_id}"] = {
        "secret": secret,
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }
    
    print(f"✅ [2FA-SETUP] Secreto generado para: {email}")
    print(f"🔐 [2FA-SETUP] ==================== FIN ====================")
    
    return {
        "secret": secret,
        "qr_code": qr_code,
        "manual_key": secret
    }


@router.post("/verify")
async def verify_2fa(request: Request, verify_data: Verify2FARequest, current_user: dict = Depends(get_current_user)):
    """Verificar código y activar 2FA"""
    supabase = get_supabase_client()
    user_id = current_user.get("sub")
    email = current_user.get("email")
    client_info = get_client_info(request)
    
    print(f"🔐 [2FA-VERIFY] Verificando código para: {email}")
    
    # Verificar código
    totp = pyotp.TOTP(verify_data.secret)
    if not totp.verify(verify_data.code):
        print(f"❌ [2FA-VERIFY] Código inválido para: {email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código inválido"
        )
    
    # Generar códigos de respaldo
    backup_codes = []
    for i in range(10):
        backup_code = f"{random.randint(100000, 999999)}"
        backup_codes.append(backup_code)
    
    # Guardar en base de datos
    supabase.table("profiles").update({
        "two_factor_secret": verify_data.secret,
        "two_factor_enabled": True
    }).eq("id", user_id).execute()
    
    # Limpiar token de setup
    if f"2fa_setup_{user_id}" in setup_tokens:
        del setup_tokens[f"2fa_setup_{user_id}"]
    
    # Registrar cambio de seguridad
    await log_security_change(
        user_id=user_id,
        change_type="2fa_enable",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        status="success",
        details={"device": client_info["device_name"]}
    )
    
    await log_activity(
        user_id=user_id,
        action="2fa_enabled",
        details={"device": client_info["device_name"]},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    print(f"✅ [2FA-VERIFY] 2FA activado para: {email}")
    
    return {
        "success": True,
        "backup_codes": backup_codes
    }


@router.post("/disable")
async def disable_2fa(request: Request, current_user: dict = Depends(get_current_user)):
    """Desactivar 2FA"""
    supabase = get_supabase_client()
    user_id = current_user.get("sub")
    email = current_user.get("email")
    client_info = get_client_info(request)
    
    print(f"🔐 [2FA-DISABLE] Desactivando 2FA para: {email}")
    
    supabase.table("profiles").update({
        "two_factor_secret": None,
        "two_factor_enabled": False
    }).eq("id", user_id).execute()
    
    # Registrar cambio de seguridad
    await log_security_change(
        user_id=user_id,
        change_type="2fa_disable",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        status="success",
        details={"device": client_info["device_name"]}
    )
    
    await log_activity(
        user_id=user_id,
        action="2fa_disabled",
        details={"device": client_info["device_name"]},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    print(f"✅ [2FA-DISABLE] 2FA desactivado para: {email}")
    return {"message": "2FA desactivado correctamente"}


# ============================================
# VERIFICAR LOGIN 2FA
# ============================================

@router.post("/verify-login", response_model=TokenResponse)
async def verify_login_2fa(request: Request, request_data: VerifyLogin2FARequest):
    """Verificar código 2FA durante el login y crear sesión"""
    
    print(f"🔐 [2FA-VERIFY-LOGIN] Verificando código")
    print(f"🔐 [2FA-VERIFY-LOGIN] Token recibido: {request_data.temp_token[:30] if request_data.temp_token else 'None'}...")
    print(f"🔐 [2FA-VERIFY-LOGIN] Tokens activos: {list(two_factor_tokens.keys())}")
    
    client_info = get_client_info(request)
    
    # Buscar token temporal
    if request_data.temp_token not in two_factor_tokens:
        print(f"❌ [2FA-VERIFY-LOGIN] Token no encontrado")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido o expirado"
        )
    
    token_data = two_factor_tokens[request_data.temp_token]
    print(f"✅ [2FA-VERIFY-LOGIN] Token encontrado para usuario: {token_data.get('email')}")
    
    # Verificar expiración
    if datetime.utcnow() > token_data["expires_at"]:
        print(f"❌ [2FA-VERIFY-LOGIN] Token expirado")
        del two_factor_tokens[request_data.temp_token]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token expirado. Por favor, inicia sesión nuevamente"
        )
    
    secret = token_data.get("secret")
    user_id = token_data.get("user_id")
    email = token_data.get("email")
    
    print(f"🔐 [2FA-VERIFY-LOGIN] Verificando código para: {email}")
    
    # Verificar código 2FA
    totp = pyotp.TOTP(secret)
    if not totp.verify(request_data.code):
        token_data["attempts"] = token_data.get("attempts", 0) + 1
        remaining = 3 - token_data["attempts"]
        print(f"❌ [2FA-VERIFY-LOGIN] Código inválido. Intentos restantes: {remaining}")
        
        if token_data["attempts"] >= 3:
            print(f"❌ [2FA-VERIFY-LOGIN] Demasiados intentos fallidos")
            del two_factor_tokens[request_data.temp_token]
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Demasiados intentos fallidos. Por favor, inicia sesión nuevamente"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Código inválido. Te quedan {remaining} intentos"
        )
    
    # Generar nuevo token JWT
    from ..auth import create_access_token
    
    # Obtener el perfil completo con el rol
    supabase = get_supabase_client()
    profile_response = supabase.table("profiles").select("*").eq("id", user_id).execute()
    profile = profile_response.data[0] if profile_response.data else {}
    
    # Obtener el rol del usuario
    user_role = profile.get("role", "user")
    print(f"🔐 [2FA-VERIFY-LOGIN] Rol del usuario: {user_role}")
    
    # Crear token con el rol incluido
    access_token = create_access_token(data={
        "sub": user_id, 
        "email": email, 
        "role": user_role
    })
    print(f"✅ [2FA-VERIFY-LOGIN] Access token generado con rol: {user_role}")
    
    # Crear sesión después de 2FA
    try:
        await create_user_session(request, user_id, email, access_token)
        print(f"✅ [2FA-VERIFY-LOGIN] Sesión creada exitosamente para {email}")
    except Exception as e:
        print(f"⚠️ [2FA-VERIFY-LOGIN] Error creando sesión: {str(e)}")
    
    # Registrar login exitoso con 2FA
    try:
        await log_login_history(
            user_id=user_id,
            email=email,
            login_type="2fa",
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            device_info=client_info,
            status="success"
        )
        print(f"✅ [2FA-VERIFY-LOGIN] Login history registrado")
    except Exception as e:
        print(f"⚠️ [2FA-VERIFY-LOGIN] Error registrando login history: {str(e)}")
    
    # Registrar actividad
    try:
        await log_activity(
            user_id=user_id,
            action="login",
            details={"login_type": "2fa", "device": client_info["device_name"]},
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        print(f"✅ [2FA-VERIFY-LOGIN] Activity log registrado")
    except Exception as e:
        print(f"⚠️ [2FA-VERIFY-LOGIN] Error registrando activity: {str(e)}")
    
    # Limpiar token temporal
    del two_factor_tokens[request_data.temp_token]
    
    print(f"✅ [2FA-VERIFY-LOGIN] Login completado exitosamente para: {email}")
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        refresh_token=None,
        requires_2fa=False,
        temp_token=None,
        message="2FA verificado correctamente",
        user=UserResponse(
            id=user_id,
            email=email,
            full_name=profile.get("full_name"),
            avatar_url=profile.get("avatar_url"),
            banner_url=profile.get("banner_url"),
            currency=profile.get("currency", "USD"),
            monthly_budget=float(profile.get("monthly_budget", 1000)) if profile.get("monthly_budget") else 1000.0,
            role=user_role,
            two_factor_enabled=True,
            created_at=profile.get("created_at"),
            updated_at=profile.get("updated_at")
        )
    )


# ============================================
# VERIFICAR CÓDIGO DE RESPALDO
# ============================================

@router.post("/verify-backup-code", response_model=TokenResponse)
async def verify_backup_code(request: Request, backup_code: str, temp_token: str):
    """Verificar código de respaldo de 2FA (para cuando no se tiene el autenticador)"""
    
    print(f"🔐 [2FA-BACKUP] Verificando código de respaldo")
    
    client_info = get_client_info(request)
    
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
    
    user_id = token_data.get("user_id")
    email = token_data.get("email")
    
    # Aquí deberías verificar contra los códigos de respaldo almacenados
    # Por ahora, permitimos cualquier código de 6 dígitos como respaldo
    if not backup_code.isdigit() or len(backup_code) != 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de respaldo inválido"
        )
    
    # Obtener perfil con rol
    supabase = get_supabase_client()
    profile_response = supabase.table("profiles").select("*").eq("id", user_id).execute()
    profile = profile_response.data[0] if profile_response.data else {}
    user_role = profile.get("role", "user")
    
    # Generar nuevo token JWT
    from ..auth import create_access_token
    access_token = create_access_token(data={"sub": user_id, "email": email, "role": user_role})
    
    # Crear sesión
    await create_user_session(request, user_id, email, access_token)
    
    # Registrar login con backup code
    await log_login_history(
        user_id=user_id,
        email=email,
        login_type="backup_code",
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        device_info=client_info,
        status="success"
    )
    
    await log_activity(
        user_id=user_id,
        action="login",
        details={"login_type": "backup_code", "device": client_info["device_name"]},
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    del two_factor_tokens[temp_token]
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        refresh_token=None,
        requires_2fa=False,
        temp_token=None,
        message="Verificación con código de respaldo exitosa",
        user=UserResponse(
            id=user_id,
            email=email,
            full_name=profile.get("full_name"),
            avatar_url=profile.get("avatar_url"),
            banner_url=profile.get("banner_url"),
            currency=profile.get("currency", "USD"),
            monthly_budget=float(profile.get("monthly_budget", 1000)) if profile.get("monthly_budget") else 1000.0,
            role=user_role,
            two_factor_enabled=True,
            created_at=profile.get("created_at"),
            updated_at=profile.get("updated_at")
        )
    )