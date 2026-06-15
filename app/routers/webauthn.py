# backend/app/routers/webauthn.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import List, Dict, Any
import json
import base64
import os
from datetime import datetime

from app.database import get_supabase_client, get_supabase_admin
from app.auth import create_access_token
from app.auth_utils import get_current_user

router = APIRouter(prefix="/webauthn", tags=["webauthn"])
security = HTTPBearer()

# ============================================
# MODELOS DE DATOS
# ============================================

class RegistrationBeginResponse(BaseModel):
    publicKey: Dict[str, Any]

class RegistrationCompleteRequest(BaseModel):
    id: str
    type: str
    response: Dict[str, Any]

class AuthenticationBeginResponse(BaseModel):
    publicKey: Dict[str, Any]

class AuthenticationCompleteRequest(BaseModel):
    id: str
    type: str
    response: Dict[str, Any]

class CredentialResponse(BaseModel):
    id: str
    name: str
    createdAt: str
    lastUsedAt: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    avatar_url: str | None = None
    banner_url: str | None = None
    currency: str = "USD"
    monthly_budget: float = 1000
    two_factor_enabled: bool = False

class LoginCompleteResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# ============================================
# HELPER FUNCTIONS
# ============================================

def generate_challenge() -> str:
    """Genera un challenge aleatorio de 32 bytes en base64 URL-safe"""
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

def to_base64url(data: bytes) -> str:
    """Convierte bytes a base64url sin padding"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

# Almacenamiento temporal de challenges
_challenges_store: Dict[str, Dict[str, Any]] = {}

# ============================================
# ENDPOINTS DE REGISTRO
# ============================================

@router.post("/register/begin", response_model=RegistrationBeginResponse)
async def register_begin(
    current_user: dict = Depends(get_current_user)
):
    """Inicia el registro de una nueva passkey"""
    
    user_id = current_user.get('id')
    user_email = current_user.get('email')
    user_name = current_user.get('full_name') or user_email.split('@')[0]
    
    print(f"🔐 [WebAuthn] Iniciando registro para: {user_email}")
    
    challenge = generate_challenge()
    
    _challenges_store[f"register_{user_id}"] = {
        'challenge': challenge,
        'created_at': datetime.now().isoformat()
    }
    
    user_id_base64 = to_base64url(user_id.encode('utf-8'))
    
    public_key = {
        "challenge": challenge,
        "rp": {
            "id": "localhost",
            "name": "Flutter Play"
        },
        "user": {
            "id": user_id_base64,
            "name": user_email,
            "displayName": user_name
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "residentKey": "required",
            "userVerification": "required"
        },
        "timeout": 60000,
        "attestation": "none"
    }
    
    print(f"🔐 [WebAuthn] Opciones de registro preparadas")
    
    return RegistrationBeginResponse(publicKey=public_key)


@router.post("/register/complete")
async def register_complete(
    request: RegistrationCompleteRequest,
    current_user: dict = Depends(get_current_user)
):
    """Completa el registro de una passkey"""
    
    user_id = current_user.get('id')
    user_email = current_user.get('email')
    
    print(f"🔐 [WebAuthn] Completando registro para: {user_email}")
    
    store_key = f"register_{user_id}"
    if store_key not in _challenges_store:
        raise HTTPException(status_code=400, detail="No hay registro pendiente")
    
    challenge_data = _challenges_store[store_key]
    stored_challenge = challenge_data['challenge']
    
    del _challenges_store[store_key]
    
    client_data_json = bytes(request.response.get('clientDataJSON', []))
    
    try:
        client_data = json.loads(client_data_json.decode('utf-8'))
        received_challenge = client_data.get('challenge', '')
        
        if received_challenge != stored_challenge:
            raise HTTPException(status_code=400, detail="Challenge invalido")
    except json.JSONDecodeError as e:
        print(f"Error parsing client data: {e}")
    
    credential_id = request.id
    
    supabase = get_supabase_admin()
    
    credential_data = {
        'credential_id': credential_id,
        'client_data_json': list(client_data_json),
        'attestation_object': list(bytes(request.response.get('attestationObject', []))),
        'transports': ['internal']
    }
    
    existing = supabase.table('passkeys').select('id').eq('credential_id', credential_id).execute()
    
    if existing.data:
        supabase.table('passkeys').update({
            'credential_data': json.dumps(credential_data),
            'last_used_at': datetime.now().isoformat()
        }).eq('credential_id', credential_id).execute()
    else:
        supabase.table('passkeys').insert({
            'user_id': user_id,
            'credential_id': credential_id,
            'credential_data': json.dumps(credential_data),
            'name': f"Passkey - {datetime.now().strftime('%d/%m/%Y')}",
            'created_at': datetime.now().isoformat(),
            'last_used_at': None
        }).execute()
    
    print(f"✅ Passkey registrada correctamente para {user_email}")
    
    return {"success": True, "credentialId": credential_id}


# ============================================
# ENDPOINTS DE AUTENTICACIÓN CON PASSKEY
# ============================================

@router.post("/login/begin", response_model=AuthenticationBeginResponse)
async def login_begin():
    """Inicia la autenticación con passkey - NO necesita email"""
    
    print(f"🔐 [WebAuthn] Iniciando autenticación (sin email)")
    
    supabase = get_supabase_client()
    
    passkeys_result = supabase.table('passkeys').select('credential_id, user_id').execute()
    
    if not passkeys_result.data:
        raise HTTPException(status_code=400, detail="No hay passkeys registradas")
    
    challenge = generate_challenge()
    
    _challenges_store[f"login_{challenge}"] = {
        'challenge': challenge,
        'created_at': datetime.now().isoformat()
    }
    
    allow_credentials = []
    for pk in passkeys_result.data:
        allow_credentials.append({
            "id": pk['credential_id'],
            "type": "public-key",
            "transports": ["internal"]
        })
    
    public_key = {
        "challenge": challenge,
        "rpId": "localhost",
        "allowCredentials": allow_credentials,
        "timeout": 60000,
        "userVerification": "required"
    }
    
    print(f"🔐 [WebAuthn] Opciones de autenticación preparadas con {len(allow_credentials)} credenciales")
    
    return AuthenticationBeginResponse(publicKey=public_key)


@router.post("/login/begin-without-email", response_model=AuthenticationBeginResponse)
async def login_begin_without_email():
    """
    Inicia autenticación con passkey sin necesidad de email.
    Este endpoint NO requiere autenticación previa.
    """
    
    print(f"🔐 [WebAuthn] Iniciando autenticación sin email (endpoint específico)")
    
    supabase = get_supabase_client()
    
    passkeys_result = supabase.table('passkeys').select('credential_id, user_id').execute()
    
    if not passkeys_result.data:
        raise HTTPException(status_code=400, detail="No hay passkeys registradas")
    
    print(f"🔐 [WebAuthn] Total passkeys encontradas: {len(passkeys_result.data)}")
    
    challenge = generate_challenge()
    
    _challenges_store[f"login_{challenge}"] = {
        'challenge': challenge,
        'created_at': datetime.now().isoformat()
    }
    
    allow_credentials = []
    for pk in passkeys_result.data:
        allow_credentials.append({
            "id": pk['credential_id'],
            "type": "public-key",
            "transports": ["internal"]
        })
    
    public_key = {
        "challenge": challenge,
        "rpId": "localhost",
        "allowCredentials": allow_credentials,
        "timeout": 60000,
        "userVerification": "required"
    }
    
    print(f"🔐 [WebAuthn] Opciones de autenticación preparadas con {len(allow_credentials)} credenciales")
    
    return AuthenticationBeginResponse(publicKey=public_key)


@router.post("/login/complete", response_model=LoginCompleteResponse)
async def login_complete(request: AuthenticationCompleteRequest):
    """Completa la autenticacion con passkey"""
    
    credential_id = request.id
    
    print(f"🔐 [WebAuthn] Completando autenticacion para credential: {credential_id[:30]}...")
    
    supabase = get_supabase_client()
    
    # Buscar la credencial en la base de datos
    passkey_result = supabase.table('passkeys').select('*').eq('credential_id', credential_id).execute()
    
    if not passkey_result.data:
        raise HTTPException(status_code=404, detail="Credencial no encontrada")
    
    user_id = passkey_result.data[0]['user_id']
    
    # Obtener el usuario completo de la base de datos
    user_result = supabase.table('profiles').select('*').eq('id', user_id).execute()
    
    if not user_result.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    user = user_result.data[0]
    email = user.get('email')
    full_name = user.get('full_name', '')
    avatar_url = user.get('avatar_url')
    banner_url = user.get('banner_url')
    currency = user.get('currency', 'USD')
    monthly_budget = user.get('monthly_budget', 1000)
    two_factor_enabled = user.get('two_factor_enabled', False)
    user_role = user.get('role', 'user')
    
    print(f"🔐 [WebAuthn] Usuario identificado: {email}, Rol: {user_role}")
    
    # Actualizar ultima vez que se uso
    supabase.table('passkeys').update({
        'last_used_at': datetime.now().isoformat()
    }).eq('credential_id', credential_id).execute()
    
    print(f"✅ Autenticacion completada para: {email}")
    
    # Generar token con email y rol incluidos
    access_token = create_access_token(data={
        "sub": user_id,
        "email": email,
        "role": user_role
    })
    
    print(f"✅ Token generado para usuario: {user_id}")
    print(f"   Email incluido en token: {email}")
    print(f"   Rol incluido en token: {user_role}")
    
    # Devolver respuesta con todos los campos
    return LoginCompleteResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user_id,
            email=email,
            full_name=full_name,
            avatar_url=avatar_url,
            banner_url=banner_url,
            currency=currency,
            monthly_budget=monthly_budget,
            two_factor_enabled=two_factor_enabled
        )
    )


# ============================================
# ENDPOINTS DE GESTIÓN DE CREDENCIALES
# ============================================

@router.get("/credentials", response_model=List[CredentialResponse])
async def get_credentials(current_user: dict = Depends(get_current_user)):
    """Obtiene todas las passkeys del usuario"""
    
    user_id = current_user.get('id')
    user_email = current_user.get('email')
    
    print(f"🔐 [WebAuthn] Obteniendo credenciales para: {user_email}")
    
    supabase = get_supabase_client()
    
    result = supabase.table('passkeys').select('credential_id, name, created_at, last_used_at').eq('user_id', user_id).execute()
    
    print(f"🔐 [WebAuthn] Resultado de Supabase: {len(result.data)} registro(s)")
    
    credentials = []
    for row in result.data:
        credentials.append(CredentialResponse(
            id=row['credential_id'],
            name=row.get('name', 'Passkey'),
            createdAt=row.get('created_at', datetime.now().isoformat()),
            lastUsedAt=row.get('last_used_at') or row.get('created_at', datetime.now().isoformat())
        ))
    
    print(f"✅ [WebAuthn] Devolviendo {len(credentials)} credencial(es)")
    
    return credentials


@router.get("/status")
async def get_passkey_status(current_user: dict = Depends(get_current_user)):
    """Obtiene el estado de las passkeys del usuario (si tiene o no)"""
    
    user_id = current_user.get('id')
    user_email = current_user.get('email')
    
    print(f"🔐 [WebAuthn] Verificando estado de passkeys para: {user_email}")
    
    supabase = get_supabase_client()
    
    result = supabase.table('passkeys').select('credential_id, name, created_at, last_used_at').eq('user_id', user_id).execute()
    
    credentials = []
    for row in result.data:
        credentials.append({
            "id": row['credential_id'],
            "name": row.get('name', 'Passkey'),
            "createdAt": row.get('created_at', datetime.now().isoformat()),
            "lastUsedAt": row.get('last_used_at') or row.get('created_at', datetime.now().isoformat())
        })
    
    return {
        "enabled": len(credentials) > 0,
        "count": len(credentials),
        "credentials": credentials
    }


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Elimina una passkey"""
    
    user_id = current_user.get('id')
    user_email = current_user.get('email')
    
    print(f"🔐 [WebAuthn] Eliminando credencial para: {user_email}")
    print(f"   Credential ID: {credential_id[:30]}...")
    
    supabase = get_supabase_admin()
    
    # Verificar que la credencial pertenece al usuario
    result = supabase.table('passkeys').select('id').eq('credential_id', credential_id).eq('user_id', user_id).execute()
    
    if not result.data:
        print(f"❌ [WebAuthn] Credencial no encontrada o no pertenece al usuario")
        raise HTTPException(status_code=404, detail="Credencial no encontrada")
    
    # Eliminar
    supabase.table('passkeys').delete().eq('credential_id', credential_id).execute()
    
    print(f"✅ [WebAuthn] Credencial eliminada correctamente")
    
    return {"success": True}