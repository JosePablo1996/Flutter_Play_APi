from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel
from ..database import get_supabase_client, get_supabase_admin
from ..dependencies import get_current_user
from ..services.email_service import EmailService
from ..services.device_alert import send_new_device_alert
import secrets
import re

# Intentar importar user_agents, si no está disponible, usar funciones alternativas
try:
    from user_agents import parse
    HAS_USER_AGENTS = True
except ImportError:
    HAS_USER_AGENTS = False
    print("⚠️ [WARNING] user-agents no instalado. Usando detección básica de dispositivos.")

router = APIRouter(prefix="/sessions", tags=["Sesiones"])

# ============================================
# MODELOS
# ============================================

class SessionResponse(BaseModel):
    id: str
    device_name: str
    device_type: str
    browser: str
    os: str
    ip_address: str
    location: str
    is_current: bool
    last_activity: datetime
    created_at: datetime

class ActivityLogResponse(BaseModel):
    id: str
    action: str
    details: Optional[dict]
    ip_address: Optional[str]
    location: Optional[str]
    status: str
    created_at: datetime

class LoginHistoryResponse(BaseModel):
    id: str
    login_type: str
    ip_address: Optional[str]
    device_name: Optional[str]
    device_type: Optional[str]
    browser: Optional[str]
    os: Optional[str]
    location: Optional[str]
    status: str
    created_at: datetime

class SecurityChangeResponse(BaseModel):
    id: str
    change_type: str
    old_value: Optional[str]
    new_value: Optional[str]
    ip_address: Optional[str]
    location: Optional[str]
    status: str
    created_at: datetime

# ============================================
# FUNCIONES AVANZADAS DE DETECCIÓN DE DISPOSITIVO
# ============================================

def parse_user_agent_fallback(user_agent: str):
    """Parseo básico de User-Agent cuando user-agents no está instalado"""
    ua = user_agent.lower()
    
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
        os_family = "Windows"
    elif 'mac' in ua:
        os_family = "macOS"
    elif 'linux' in ua:
        os_family = "Linux"
    elif 'android' in ua:
        os_family = "Android"
    elif 'ios' in ua or 'iphone' in ua or 'ipad' in ua:
        os_family = "iOS"
    else:
        os_family = "Unknown"
    
    # Detectar tipo de dispositivo
    if 'mobile' in ua or 'android' in ua:
        is_mobile = True
        is_tablet = False
        is_pc = False
    elif 'tablet' in ua or 'ipad' in ua:
        is_mobile = False
        is_tablet = True
        is_pc = False
    elif 'windows' in ua or 'mac' in ua or 'linux' in ua:
        is_mobile = False
        is_tablet = False
        is_pc = True
    else:
        is_mobile = False
        is_tablet = False
        is_pc = False
    
    return type('obj', (object,), {
        'browser': type('obj', (object,), {'family': browser})(),
        'os': type('obj', (object,), {'family': os_family})(),
        'is_mobile': is_mobile,
        'is_tablet': is_tablet,
        'is_pc': is_pc
    })()


def get_device_model(user_agent: str) -> str:
    """Detectar modelo específico del dispositivo desde el User-Agent"""
    ua = user_agent.lower()
    
    # ============================================
    # LAPTOPS / PCs
    # ============================================
    if 'thinkpad' in ua:
        return "Lenovo ThinkPad"
    elif 'latitude' in ua:
        return "Dell Latitude"
    elif 'xps' in ua:
        return "Dell XPS"
    elif 'macbook' in ua:
        return "Apple MacBook"
    elif 'surface' in ua:
        return "Microsoft Surface"
    elif 'spectre' in ua:
        return "HP Spectre"
    elif 'elitebook' in ua:
        return "HP EliteBook"
    elif 'precision' in ua:
        return "Dell Precision"
    elif 'ideapad' in ua:
        return "Lenovo IdeaPad"
    elif 'yoga' in ua:
        return "Lenovo Yoga"
    elif 'zenbook' in ua:
        return "ASUS ZenBook"
    elif 'rog' in ua:
        return "ASUS ROG"
    elif 'legion' in ua:
        return "Lenovo Legion"
    
    # ============================================
    # SAMSUNG GALAXY
    # ============================================
    elif 'sm-a' in ua or 'galaxy a' in ua:
        match = re.search(r'SM-A\d+', ua.upper())
        if match:
            return f"Samsung Galaxy {match.group()}"
        return "Samsung Galaxy A Series"
    elif 'sm-s' in ua or 'galaxy s' in ua:
        match = re.search(r'SM-S\d+', ua.upper())
        if match:
            return f"Samsung Galaxy {match.group()}"
        return "Samsung Galaxy S Series"
    elif 'sm-z' in ua or 'galaxy z' in ua:
        return "Samsung Galaxy Z Series"
    elif 'sm-n' in ua or 'galaxy note' in ua:
        return "Samsung Galaxy Note"
    elif 'samsung' in ua:
        return "Samsung Galaxy"
    
    # ============================================
    # POCO / XIAOMI
    # ============================================
    elif 'poco x6 pro' in ua:
        return "POCO X6 Pro"
    elif 'poco x7 pro' in ua:
        return "POCO X7 Pro"
    elif 'poco f6' in ua:
        return "POCO F6"
    elif 'poco m6' in ua:
        return "POCO M6"
    elif 'poco' in ua:
        return "POCO Phone"
    elif 'redmi pad' in ua:
        return "Redmi Pad SE"
    elif 'redmi note' in ua:
        return "Redmi Note"
    elif 'redmi' in ua:
        return "Redmi Phone"
    elif 'xiaomi 13' in ua:
        return "Xiaomi 13"
    elif 'xiaomi 12' in ua:
        return "Xiaomi 12"
    elif 'xiaomi 14' in ua:
        return "Xiaomi 14"
    elif 'xiaomi mix' in ua:
        return "Xiaomi Mix"
    elif 'xiaomi' in ua:
        return "Xiaomi Phone"
    
    # ============================================
    # ONEPLUS
    # ============================================
    elif 'oneplus' in ua:
        match = re.search(r'oneplus\s?(\d+)', ua)
        if match:
            return f"OnePlus {match.group(1)}"
        return "OnePlus Phone"
    
    # ============================================
    # GOOGLE PIXEL
    # ============================================
    elif 'pixel' in ua:
        match = re.search(r'pixel\s?(\d+)', ua)
        if match:
            return f"Google Pixel {match.group(1)}"
        return "Google Pixel"
    
    # ============================================
    # HUAWEI / HONOR
    # ============================================
    elif 'huawei' in ua:
        return "Huawei Phone"
    elif 'honor' in ua:
        return "Honor Phone"
    
    # ============================================
    # APPLE IPHONE / IPAD
    # ============================================
    elif 'iphone' in ua:
        match = re.search(r'iphone(\d+,\d+)', ua)
        if match:
            model_map = {
                "14,2": "iPhone 13 Pro", "14,3": "iPhone 13 Pro Max",
                "14,4": "iPhone 13 mini", "14,5": "iPhone 13",
                "15,2": "iPhone 14 Pro", "15,3": "iPhone 14 Pro Max",
                "15,4": "iPhone 14", "15,5": "iPhone 14 Plus",
                "16,1": "iPhone 15 Pro", "16,2": "iPhone 15 Pro Max",
                "16,3": "iPhone 15", "16,4": "iPhone 15 Plus",
                "17,1": "iPhone 16 Pro", "17,2": "iPhone 16 Pro Max",
                "17,3": "iPhone 16", "17,4": "iPhone 16 Plus",
            }
            return model_map.get(match.group(1), "iPhone")
        return "iPhone"
    elif 'ipad' in ua:
        return "iPad"
    
    # ============================================
    # MOTOROLA
    # ============================================
    elif 'moto g' in ua:
        return "Motorola Moto G"
    elif 'moto e' in ua:
        return "Motorola Moto E"
    elif 'motorola' in ua:
        return "Motorola Phone"
    
    # ============================================
    # POR DEFECTO
    # ============================================
    elif 'windows' in ua:
        return "PC Windows"
    elif 'mac' in ua:
        return "Mac"
    elif 'linux' in ua:
        return "PC Linux"
    elif 'android' in ua:
        return "Dispositivo Android"
    elif 'ios' in ua:
        return "Dispositivo iOS"
    
    return "Dispositivo Desconocido"


def get_device_brand(user_agent: str) -> str:
    """Detectar la marca del dispositivo"""
    ua = user_agent.lower()
    
    if 'samsung' in ua or 'sm-' in ua:
        return "Samsung"
    elif 'poco' in ua:
        return "POCO"
    elif 'xiaomi' in ua or 'redmi' in ua:
        return "Xiaomi"
    elif 'oneplus' in ua:
        return "OnePlus"
    elif 'google' in ua or 'pixel' in ua:
        return "Google"
    elif 'huawei' in ua:
        return "Huawei"
    elif 'honor' in ua:
        return "Honor"
    elif 'iphone' in ua or 'ipad' in ua:
        return "Apple"
    elif 'macbook' in ua or 'mac' in ua:
        return "Apple"
    elif 'lenovo' in ua or 'thinkpad' in ua:
        return "Lenovo"
    elif 'dell' in ua:
        return "Dell"
    elif 'hp' in ua or 'elitebook' in ua or 'spectre' in ua:
        return "HP"
    elif 'asus' in ua:
        return "ASUS"
    elif 'microsoft' in ua or 'surface' in ua:
        return "Microsoft"
    elif 'motorola' in ua or 'moto' in ua:
        return "Motorola"
    elif 'nokia' in ua:
        return "Nokia"
    elif 'sony' in ua:
        return "Sony"
    else:
        return "Desconocido"


def get_device_fingerprint(user_agent: str) -> str:
    """Genera una huella digital única del dispositivo"""
    device_model = get_device_model(user_agent)
    device_brand = get_device_brand(user_agent)
    
    # Parsear SO
    if HAS_USER_AGENTS:
        ua = parse(user_agent)
        os_family = ua.os.family if ua.os else "Unknown"
        
        if ua.is_mobile:
            device_family = "Mobile"
        elif ua.is_tablet:
            device_family = "Tablet"
        elif ua.is_pc:
            device_family = "Desktop"
        else:
            device_family = "Unknown"
    else:
        ua_parsed = parse_user_agent_fallback(user_agent)
        os_family = ua_parsed.os.family
        
        if ua_parsed.is_mobile:
            device_family = "Mobile"
        elif ua_parsed.is_tablet:
            device_family = "Tablet"
        elif ua_parsed.is_pc:
            device_family = "Desktop"
        else:
            device_family = "Unknown"
    
    # Fingerprint basado en marca + modelo + SO + tipo
    fingerprint = f"{device_brand}|{device_model}|{os_family}|{device_family}"
    
    return fingerprint


def get_client_info(request: Request) -> dict:
    """Extraer información avanzada del cliente desde la request"""
    user_agent = request.headers.get("user-agent", "")
    
    if HAS_USER_AGENTS:
        ua = parse(user_agent)
        
        # Detectar tipo de dispositivo
        if ua.is_mobile:
            device_type = "Mobile"
        elif ua.is_tablet:
            device_type = "Tablet"
        elif ua.is_pc:
            device_type = "Desktop"
        else:
            device_type = "Unknown"
        
        # Detectar navegador
        browser = ua.browser.family if ua.browser else "Unknown"
        
        # Detectar SO
        os_name = ua.os.family if ua.os else "Unknown"
    else:
        ua_parsed = parse_user_agent_fallback(user_agent)
        
        if ua_parsed.is_mobile:
            device_type = "Mobile"
        elif ua_parsed.is_tablet:
            device_type = "Tablet"
        elif ua_parsed.is_pc:
            device_type = "Desktop"
        else:
            device_type = "Unknown"
        
        browser = ua_parsed.browser.family
        os_name = ua_parsed.os.family
    
    # Modelo y marca específicos
    device_model = get_device_model(user_agent)
    device_brand = get_device_brand(user_agent)
    
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
    
    # Generar nombre de dispositivo legible
    if device_model != "Dispositivo Desconocido":
        if device_brand != "Desconocido" and device_brand not in device_model:
            device_name = f"{device_brand} {device_model} ({browser})"
        else:
            device_name = f"{device_model} ({browser})"
    else:
        device_name = f"{device_type} - {os_name} ({browser})"
    
    # Generar huella digital única
    device_fingerprint = get_device_fingerprint(user_agent)
    
    return {
        "device_type": device_type,
        "browser": browser,
        "os": os_name,
        "device_brand": device_brand,
        "device_model": device_model,
        "device_name": device_name,
        "device_fingerprint": device_fingerprint,
        "ip_address": ip_address,
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
    """Registrar historial de inicio de sesión con información avanzada de dispositivo"""
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
            "device_brand": device_info.get("device_brand") if device_info else None,
            "device_model": device_info.get("device_model") if device_info else None,
            "browser": device_info.get("browser") if device_info else None,
            "os": device_info.get("os") if device_info else None,
            "device_fingerprint": device_info.get("device_fingerprint") if device_info else None,
            "location": location or "Ubicación desconocida",
            "status": status,
            "created_at": datetime.utcnow().isoformat()
        }
        
        result = supabase_admin.table("login_history").insert(login_data).execute()
        print(f"✅ [LOGIN_HISTORY] Registrado: {login_type} para {email}")
        print(f"   Dispositivo: {login_data.get('device_name')}")
        if login_data.get('device_brand'):
            print(f"   Marca: {login_data.get('device_brand')}")
        if login_data.get('device_model'):
            print(f"   Modelo: {login_data.get('device_model')}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"⚠️ [LOGIN_HISTORY] Error: {str(e)}")
        return None


# ============================================
# FUNCIONES DE SESIÓN
# ============================================

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
            "device_brand": client_info.get("device_brand"),
            "device_model": client_info.get("device_model"),
            "browser": client_info["browser"],
            "os": client_info["os"],
            "device_fingerprint": client_info["device_fingerprint"],
            "location": "Ubicación desconocida",
            "is_current": True,
            "last_activity": datetime.utcnow().isoformat(),
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
        }
        
        result = supabase_admin.table("user_sessions").insert(session_data).execute()
        print(f"✅ [CREATE_SESSION] Sesión creada para {email}")
        print(f"   Dispositivo: {session_data.get('device_name')}")
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"❌ [CREATE_SESSION] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


# ============================================
# ENDPOINTS DE SESIONES
# ============================================

@router.get("/", response_model=List[SessionResponse])
async def get_sessions(request: Request, current_user: dict = Depends(get_current_user)):
    """Obtener todas las sesiones activas del usuario"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"🔍 [GET_SESSIONS] Usuario: {email} (ID: {user_id})")
    
    auth_header = request.headers.get("authorization", "")
    current_token = None
    if auth_header.startswith("Bearer "):
        current_token = auth_header.replace("Bearer ", "")
    
    supabase = get_supabase_admin()
    
    try:
        response = supabase.table("user_sessions").select("*")\
            .eq("user_id", user_id)\
            .order("last_activity", desc=True)\
            .execute()
        
        print(f"📊 [GET_SESSIONS] Encontradas {len(response.data) if response.data else 0} sesiones")
        
        if not response.data:
            return []
        
        sessions = []
        for session in response.data:
            is_current = False
            if current_token and session.get("session_token"):
                is_current = (session["session_token"] == current_token)
            
            last_activity = session.get("last_activity")
            if isinstance(last_activity, str):
                last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
            elif not last_activity:
                last_activity = datetime.now()
            
            created_at = session.get("created_at")
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            elif not created_at:
                created_at = datetime.now()
            
            # Usar device_model si está disponible
            device_name = session.get("device_model") or session.get("device_name", "Dispositivo desconocido")
            if session.get("device_brand") and session.get("device_brand") != "Desconocido":
                if session.get("device_brand") not in device_name:
                    device_name = f"{session.get('device_brand')} {device_name}"
            
            sessions.append(SessionResponse(
                id=session["id"],
                device_name=device_name,
                device_type=session.get("device_type", "Unknown"),
                browser=session.get("browser", "Unknown"),
                os=session.get("os", "Unknown"),
                ip_address=session.get("ip_address", "Unknown"),
                location=session.get("location") or "Ubicación desconocida",
                is_current=is_current,
                last_activity=last_activity,
                created_at=created_at
            ))
        
        return sessions
        
    except Exception as e:
        print(f"❌ [GET_SESSIONS] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return []


@router.post("/create")
async def create_session_endpoint(request: Request, current_user: dict = Depends(get_current_user)):
    """Crear una nueva sesión para el usuario actual"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    session = await create_user_session(request, user_id, email)
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear la sesión"
        )
    
    return {"message": "Sesión creada correctamente", "session": session}


@router.post("/revoke")
async def revoke_session(session_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Revocar una sesión específica"""
    supabase_admin = get_supabase_admin()
    user_id = current_user.get("sub")
    client_info = get_client_info(request)
    
    # Verificar que la sesión pertenece al usuario
    check = supabase_admin.table("user_sessions").select("*")\
        .eq("id", session_id).eq("user_id", user_id).execute()
    
    if not check.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sesión no encontrada"
        )
    
    session_info = check.data[0]
    
    # Eliminar la sesión
    supabase_admin.table("user_sessions").delete().eq("id", session_id).execute()
    
    # Registrar actividad
    await log_activity(
        user_id=user_id,
        action="session_revoked",
        details={
            "session_id": session_id,
            "revoked_device": session_info.get("device_model") or session_info.get("device_name", "Desconocido"),
            "current_device": client_info.get("device_model") or client_info["device_name"]
        },
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    return {"message": "Sesión cerrada correctamente"}


@router.post("/revoke-all")
async def revoke_all_sessions(request: Request, current_user: dict = Depends(get_current_user)):
    """Revocar todas las sesiones excepto la actual"""
    supabase_admin = get_supabase_admin()
    user_id = current_user.get("sub")
    client_info = get_client_info(request)
    
    auth_header = request.headers.get("authorization", "")
    current_token = None
    if auth_header.startswith("Bearer "):
        current_token = auth_header.replace("Bearer ", "")
    
    # Obtener información de las sesiones que se van a cerrar
    sessions_to_revoke = supabase_admin.table("user_sessions").select("*")\
        .eq("user_id", user_id)\
        .execute()
    
    revoked_count = 0
    revoked_devices = []
    
    if current_token:
        for session in sessions_to_revoke.data:
            if session.get("session_token") != current_token:
                device_name = session.get("device_model") or session.get("device_name", "Desconocido")
                if session.get("device_brand") and session.get("device_brand") != "Desconocido":
                    if session.get("device_brand") not in device_name:
                        device_name = f"{session.get('device_brand')} {device_name}"
                revoked_devices.append(device_name)
                revoked_count += 1
        supabase_admin.table("user_sessions").delete()\
            .eq("user_id", user_id)\
            .neq("session_token", current_token)\
            .execute()
    else:
        for session in sessions_to_revoke.data:
            device_name = session.get("device_model") or session.get("device_name", "Desconocido")
            if session.get("device_brand") and session.get("device_brand") != "Desconocido":
                if session.get("device_brand") not in device_name:
                    device_name = f"{session.get('device_brand')} {device_name}"
            revoked_devices.append(device_name)
            revoked_count += 1
        supabase_admin.table("user_sessions").delete().eq("user_id", user_id).execute()
    
    # Registrar actividad
    await log_activity(
        user_id=user_id,
        action="all_sessions_revoked",
        details={
            "revoked_count": revoked_count,
            "revoked_devices": revoked_devices,
            "current_device": client_info.get("device_model") or client_info["device_name"]
        },
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    
    return {
        "message": f"Todas las sesiones han sido cerradas. Se cerraron {revoked_count} sesiones.",
        "revoked_count": revoked_count
    }


@router.post("/update-activity")
async def update_activity(request: Request, current_user: dict = Depends(get_current_user)):
    """Actualizar la última actividad de la sesión actual"""
    supabase_admin = get_supabase_admin()
    user_id = current_user.get("sub")
    
    auth_header = request.headers.get("authorization", "")
    current_token = None
    if auth_header.startswith("Bearer "):
        current_token = auth_header.replace("Bearer ", "")
    
    if not current_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se pudo identificar la sesión actual"
        )
    
    supabase_admin.table("user_sessions")\
        .update({"last_activity": datetime.utcnow().isoformat()})\
        .eq("user_id", user_id)\
        .eq("session_token", current_token)\
        .execute()
    
    return {"message": "Actividad actualizada"}


# ============================================
# ENDPOINTS DE HISTORIAL
# ============================================

@router.get("/activity", response_model=List[ActivityLogResponse])
async def get_activity_log(
    limit: int = 50,
    offset: int = 0,
    action_filter: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Obtener historial de actividad del usuario"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"📋 [GET_ACTIVITY] Usuario: {email} (ID: {user_id})")
    
    supabase = get_supabase_admin()
    
    try:
        query = supabase.table("activity_log").select("*")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(min(limit, 100))\
            .offset(offset)
        
        if action_filter:
            query = query.eq("action", action_filter)
        
        response = query.execute()
        
        activities = []
        for act in response.data:
            created_at = act.get("created_at")
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            elif not created_at:
                created_at = datetime.now()
            
            activities.append(ActivityLogResponse(
                id=act["id"],
                action=act["action"],
                details=act.get("details"),
                ip_address=act.get("ip_address"),
                location=act.get("location") or "Ubicación desconocida",
                status=act.get("status", "success"),
                created_at=created_at
            ))
        
        return activities
        
    except Exception as e:
        print(f"❌ [GET_ACTIVITY] Error: {str(e)}")
        return []


@router.get("/login-history", response_model=List[LoginHistoryResponse])
async def get_login_history(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """Obtener historial de inicios de sesión"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"📋 [GET_LOGIN_HISTORY] Usuario: {email} (ID: {user_id})")
    
    supabase = get_supabase_admin()
    
    try:
        response = supabase.table("login_history").select("*")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(min(limit, 100))\
            .offset(offset)\
            .execute()
        
        history = []
        for item in response.data:
            created_at = item.get("created_at")
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            elif not created_at:
                created_at = datetime.now()
            
            # Usar device_model si está disponible
            device_name = item.get("device_model") or item.get("device_name", "Desconocido")
            if item.get("device_brand") and item.get("device_brand") != "Desconocido":
                if item.get("device_brand") not in device_name:
                    device_name = f"{item.get('device_brand')} {device_name}"
            
            history.append(LoginHistoryResponse(
                id=item["id"],
                login_type=item["login_type"],
                ip_address=item.get("ip_address"),
                device_name=device_name,
                device_type=item.get("device_type"),
                browser=item.get("browser"),
                os=item.get("os"),
                location=item.get("location") or "Ubicación desconocida",
                status=item.get("status", "success"),
                created_at=created_at
            ))
        
        print(f"✅ [GET_LOGIN_HISTORY] Retornando {len(history)} registros")
        return history
        
    except Exception as e:
        print(f"❌ [GET_LOGIN_HISTORY] Error: {str(e)}")
        return []


@router.get("/security-changes", response_model=List[SecurityChangeResponse])
async def get_security_changes(
    limit: int = 50,
    offset: int = 0,
    change_type_filter: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Obtener historial de cambios de seguridad"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"📋 [GET_SECURITY_CHANGES] Usuario: {email} (ID: {user_id})")
    
    supabase = get_supabase_admin()
    
    try:
        query = supabase.table("security_changes").select("*")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(min(limit, 100))\
            .offset(offset)
        
        if change_type_filter:
            query = query.eq("change_type", change_type_filter)
        
        response = query.execute()
        
        changes = []
        for item in response.data:
            created_at = item.get("created_at")
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            elif not created_at:
                created_at = datetime.now()
            
            changes.append(SecurityChangeResponse(
                id=item["id"],
                change_type=item["change_type"],
                old_value=item.get("old_value"),
                new_value=item.get("new_value"),
                ip_address=item.get("ip_address"),
                location=item.get("location") or "Ubicación desconocida",
                status=item.get("status", "success"),
                created_at=created_at
            ))
        
        return changes
        
    except Exception as e:
        print(f"❌ [GET_SECURITY_CHANGES] Error: {str(e)}")
        return []


# ============================================
# ✅ ENDPOINT CORREGIDO: ESTADÍSTICAS DE SEGURIDAD
# ============================================

@router.get("/security-stats")
async def get_security_stats(current_user: dict = Depends(get_current_user)):
    """Obtener estadísticas de seguridad del usuario con detección avanzada de dispositivos"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    print(f"📊 [SECURITY_STATS] Solicitando estadísticas para: {email} (ID: {user_id})")
    
    supabase = get_supabase_admin()
    
    try:
        # Contar logins totales
        login_count = supabase.table("login_history")\
            .select("id", count="exact")\
            .eq("user_id", user_id)\
            .execute()
        
        total_logins = login_count.count if hasattr(login_count, 'count') else 0
        
        # ✅ CORRECCIÓN: Contar dispositivos únicos por combinación de device_type + os
        # Esto asegura que el mismo dispositivo físico se cuente solo una vez
        devices = supabase.table("login_history")\
            .select("device_type, os")\
            .eq("user_id", user_id)\
            .execute()
        
        unique_device_keys = set()
        for d in devices.data:
            device_type = d.get("device_type", "unknown")
            os_name = d.get("os", "unknown")
            key = f"{device_type}|{os_name}"
            unique_device_keys.add(key)
        
        unique_devices = len(unique_device_keys)
        
        print(f"✅ [SECURITY_STATS] Dispositivos únicos detectados: {unique_devices}")
        print(f"   Claves únicas: {unique_device_keys}")
        
        # Obtener último login
        last_login_data = supabase.table("login_history")\
            .select("*")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(1)\
            .execute()
        
        last_login = None
        if last_login_data.data:
            last_login_item = last_login_data.data[0]
            device_name = last_login_item.get("device_model") or last_login_item.get("device_name", "Desconocido")
            device_brand = last_login_item.get("device_brand", "")
            
            if device_brand and device_brand != "Desconocido" and device_brand not in device_name:
                device_display = f"{device_brand} {device_name}"
            else:
                device_display = device_name
            
            last_login = {
                "date": last_login_item.get("created_at"),
                "device": device_display,
                "ip": last_login_item.get("ip_address")
            }
        
        # Obtener estado de Passkey
        passkey_response = supabase.table("passkeys").select("id", count="exact").eq("user_id", user_id).execute()
        has_passkey = passkey_response.count > 0 if hasattr(passkey_response, 'count') else False
        
        # Obtener estado de 2FA
        profile_response = supabase.table("profiles").select("two_factor_enabled").eq("id", user_id).execute()
        two_factor_enabled = False
        if profile_response.data:
            two_factor_enabled = profile_response.data[0].get("two_factor_enabled", False)
        
        # Calcular puntuación de seguridad
        security_score = 40  # Base
        if total_logins > 0:
            security_score += 10
        if unique_devices == 1:
            security_score += 25
        elif unique_devices == 2:
            security_score += 15
        elif unique_devices <= 5:
            security_score += 5
        if two_factor_enabled:
            security_score += 30
        if has_passkey:
            security_score += 20
        
        security_score = min(security_score, 100)
        
        # Recomendaciones
        recommendations = []
        if not two_factor_enabled:
            recommendations.append("Activa la autenticación de dos factores (2FA) para mayor seguridad")
        if not has_passkey:
            recommendations.append("Registra una passkey para iniciar sesión sin contraseña")
        if unique_devices > 3:
            recommendations.append("Revisa tus sesiones activas y cierra las que no reconozcas")
        if total_logins == 0:
            recommendations.append("Inicia sesión para comenzar a registrar tu actividad")
        
        return {
            "total_logins": total_logins,
            "unique_devices": unique_devices,
            "last_login": last_login,
            "security_score": security_score,
            "recommendations": recommendations,
            "has_passkey": has_passkey
        }
        
    except Exception as e:
        print(f"❌ [SECURITY_STATS] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "total_logins": 0,
            "unique_devices": 0,
            "last_login": None,
            "security_score": 0,
            "recommendations": ["No se pudieron cargar las estadísticas de seguridad"],
            "has_passkey": False
        }