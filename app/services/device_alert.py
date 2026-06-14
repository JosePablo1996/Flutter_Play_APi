from datetime import datetime
from ..database import get_supabase_admin
from ..services.email_service import EmailService


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


async def send_new_device_alert(user_id: str, device_info: dict, request=None):
    """
    Enviar alerta cuando se detecta un nuevo dispositivo.
    """
    try:
        supabase_admin = get_supabase_admin()
        
        # Obtener email del usuario
        user_response = supabase_admin.table("profiles").select("email").eq("id", user_id).execute()
        user_email = user_response.data[0]["email"] if user_response.data else None
        
        if not user_email:
            print(f"⚠️ [NEW_DEVICE_ALERT] No se encontró email para usuario {user_id}")
            return False
        
        # Verificar si es un dispositivo nuevo (no registrado en login_history reciente)
        recent_logins = supabase_admin.table("login_history")\
            .select("device_name, device_type, browser, os")\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .limit(5)\
            .execute()
        
        is_new_device = True
        if recent_logins.data:
            for login in recent_logins.data:
                if (login.get("device_name") == device_info.get("device_name") or
                    (login.get("device_type") == device_info.get("device_type") and
                     login.get("browser") == device_info.get("browser") and
                     login.get("os") == device_info.get("os"))):
                    is_new_device = False
                    break
        
        if is_new_device:
            # Preparar información del dispositivo para el email
            device_alert_info = {
                "device_name": device_info.get("device_name", "Desconocido"),
                "device_type": device_info.get("device_type", "Desconocido"),
                "browser": device_info.get("browser", "Desconocido"),
                "os": device_info.get("os", "Desconocido"),
                "ip_address": device_info.get("ip_address", "Desconocida"),
                "timestamp": device_info.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            }
            
            # Enviar alerta por email
            result = await EmailService.send_new_device_alert(
                to_email=user_email,
                device_info=device_alert_info,
                name=user_id[:8]
            )
            
            if result:
                print(f"✅ [NEW_DEVICE_ALERT] Alerta enviada para nuevo dispositivo: {device_info.get('device_name')}")
                
                # Registrar en activity_log
                await log_activity(
                    user_id=user_id,
                    action="new_device_alert_sent",
                    details={"device": device_info.get("device_name")},
                    ip_address=device_info.get("ip_address"),
                    user_agent=device_info.get("user_agent")
                )
            else:
                print(f"⚠️ [NEW_DEVICE_ALERT] Error al enviar alerta para: {device_info.get('device_name')}")
            
            return result
        else:
            print(f"📱 [NEW_DEVICE_ALERT] Dispositivo ya conocido: {device_info.get('device_name')}")
            return True
            
    except Exception as e:
        print(f"❌ [NEW_DEVICE_ALERT] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False