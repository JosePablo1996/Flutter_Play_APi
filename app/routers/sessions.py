from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel
from ..database import get_supabase_client, get_supabase_admin
from ..dependencies import get_current_user
from ..services.email_service import EmailService
from ..services.device_alert import send_new_device_alert
import secrets

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
            
            sessions.append(SessionResponse(
                id=session["id"],
                device_name=session.get("device_name", "Dispositivo desconocido"),
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
            "revoked_device": session_info.get("device_name", "Desconocido"),
            "current_device": client_info["device_name"]
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
                revoked_devices.append(session.get("device_name", "Desconocido"))
                revoked_count += 1
        supabase_admin.table("user_sessions").delete()\
            .eq("user_id", user_id)\
            .neq("session_token", current_token)\
            .execute()
    else:
        for session in sessions_to_revoke.data:
            revoked_devices.append(session.get("device_name", "Desconocido"))
            revoked_count += 1
        supabase_admin.table("user_sessions").delete().eq("user_id", user_id).execute()
    
    # Registrar actividad
    await log_activity(
        user_id=user_id,
        action="all_sessions_revoked",
        details={
            "revoked_count": revoked_count,
            "revoked_devices": revoked_devices,
            "current_device": client_info["device_name"]
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
            
            history.append(LoginHistoryResponse(
                id=item["id"],
                login_type=item["login_type"],
                ip_address=item.get("ip_address"),
                device_name=item.get("device_name"),
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


@router.get("/stats")
async def get_security_stats(current_user: dict = Depends(get_current_user)):
    """Obtener estadísticas de seguridad del usuario"""
    
    user_id = current_user.get("sub")
    email = current_user.get("email")
    
    supabase = get_supabase_admin()
    
    try:
        # Contar logins totales
        login_count = supabase.table("login_history")\
            .select("id", count="exact")\
            .eq("user_id", user_id)\
            .execute()
        
        # Contar dispositivos únicos
        devices = supabase.table("login_history")\
            .select("device_name")\
            .eq("user_id", user_id)\
            .execute()
        
        unique_devices = len(set([d.get("device_name") for d in devices.data if d.get("device_name")]))
        
        # Último login
        last_login_data = supabase.table("login_history")\
            .select("*")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(1)\
            .execute()
        
        last_login = None
        if last_login_data.data:
            last_login = last_login_data.data[0]
        
        # Contar sesiones activas
        sessions_count = supabase.table("user_sessions")\
            .select("id", count="exact")\
            .eq("user_id", user_id)\
            .execute()
        
        active_sessions = sessions_count.count if hasattr(sessions_count, 'count') else 0
        
        # Calcular puntuación de seguridad
        security_score = 40  # Base
        if last_login_data.data:
            security_score += 10
        
        return {
            "total_logins": login_count.count if hasattr(login_count, 'count') else 0,
            "unique_devices": unique_devices,
            "active_sessions": active_sessions,
            "last_login": {
                "date": last_login.get("created_at") if last_login else None,
                "device": last_login.get("device_name") if last_login else None,
                "ip": last_login.get("ip_address") if last_login else None
            } if last_login else None,
            "security_score": security_score,
            "recommendations": [
                "Activa la autenticación de dos factores (2FA)" if security_score < 70 else None,
                "Revisa las sesiones activas periódicamente",
                "Cierra sesiones en dispositivos que no reconoces"
            ]
        }
        
    except Exception as e:
        print(f"❌ [GET_SECURITY_STATS] Error: {str(e)}")
        return {
            "total_logins": 0,
            "unique_devices": 0,
            "active_sessions": 0,
            "last_login": None,
            "security_score": 0,
            "recommendations": []
        }