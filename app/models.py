# backend/app/models.py
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

# ============================================
# MODELOS DE AUTENTICACIÓN
# ============================================

class UserRegister(BaseModel):
    """Modelo para registro de usuario"""
    email: EmailStr
    password: str = Field(..., min_length=6)
    full_name: str = Field(..., min_length=2)
    student_id: Optional[str] = None
    university: Optional[str] = None


class UserLogin(BaseModel):
    """Modelo para inicio de sesión"""
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Modelo de respuesta para información del usuario"""
    id: str
    email: str
    full_name: Optional[str] = None
    student_id: Optional[str] = None
    university: Optional[str] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    currency: str = "USD"
    monthly_budget: float = 1000.0
    role: str = "user"  # 👈 NUEVO: rol del usuario (admin/user)
    two_factor_enabled: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class TokenResponse(BaseModel):
    """Modelo de respuesta para autenticación"""
    access_token: str
    token_type: str = "bearer"
    refresh_token: Optional[str] = None
    user: UserResponse
    requires_2fa: Optional[bool] = False
    temp_token: Optional[str] = None


# ============================================
# MODELOS DE 2FA
# ============================================

class TwoFactorSetupResponse(BaseModel):
    """Respuesta para configuración de 2FA"""
    secret: str
    qr_code: str
    manual_key: str


class TwoFactorVerifyRequest(BaseModel):
    """Solicitud para verificar código 2FA"""
    code: str
    secret: str


class TwoFactorVerifyLoginRequest(BaseModel):
    """Solicitud para verificar 2FA durante login"""
    code: str
    temp_token: str


class TwoFactorStatusResponse(BaseModel):
    """Respuesta de estado de 2FA"""
    enabled: bool


# ============================================
# MODELOS DE GASTOS
# ============================================

class ExpenseCreate(BaseModel):
    """Modelo para crear un gasto"""
    name: str = Field(..., min_length=1, max_length=100)
    amount: float = Field(..., gt=0)
    date: str
    category: str
    description: Optional[str] = None
    is_recurring: bool = False
    recurrence_pattern: Optional[str] = None


class ExpenseUpdate(BaseModel):
    """Modelo para actualizar un gasto"""
    name: Optional[str] = None
    amount: Optional[float] = None
    date: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    is_recurring: Optional[bool] = None
    recurrence_pattern: Optional[str] = None


class ExpenseResponse(BaseModel):
    """Modelo de respuesta para gastos"""
    id: str
    user_id: str
    name: str
    amount: float
    date: str
    category: str
    description: Optional[str] = None
    receipt_url: Optional[str] = None
    is_recurring: bool
    recurrence_pattern: Optional[str] = None
    created_at: str
    updated_at: str


class ExpenseStatsResponse(BaseModel):
    """Modelo de estadísticas de gastos"""
    total: float
    count: int
    average: float


# ============================================
# MODELOS DE CATEGORÍAS
# ============================================

class CategoryCreate(BaseModel):
    """Modelo para crear una categoría"""
    name: str = Field(..., min_length=2, max_length=50)
    icon: str = Field(..., min_length=1, max_length=10)
    color: str = Field(..., pattern=r'^#[0-9A-Fa-f]{6}$')  # 👈 CORREGIDO: regex → pattern


class CategoryUpdate(BaseModel):
    """Modelo para actualizar una categoría"""
    name: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$')  # 👈 CORREGIDO


class CategoryResponse(BaseModel):
    """Modelo de respuesta para categorías"""
    id: str
    name: str
    icon: str
    color: str
    is_default: bool
    user_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


# ============================================
# MODELOS DE PRESUPUESTOS
# ============================================

class BudgetCreate(BaseModel):
    """Modelo para crear un presupuesto"""
    category: str
    amount: float = Field(..., gt=0)
    period: str = "monthly"


class BudgetUpdate(BaseModel):
    """Modelo para actualizar un presupuesto"""
    amount: Optional[float] = None
    period: Optional[str] = None


class BudgetResponse(BaseModel):
    """Modelo de respuesta para presupuestos"""
    id: str
    user_id: str
    category: str
    amount: float
    period: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class BudgetWithSpent(BaseModel):
    """Modelo de presupuesto con gasto actual"""
    id: str
    user_id: str
    category: str
    amount: float
    period: str
    spent: float
    percentage: float
    remaining: float
    isOverBudget: bool
    isNearLimit: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


# ============================================
# MODELOS DE PERFIL
# ============================================

class ProfileUpdate(BaseModel):
    """Modelo para actualizar perfil"""
    full_name: Optional[str] = None
    student_id: Optional[str] = None
    university: Optional[str] = None
    currency: Optional[str] = None
    monthly_budget: Optional[float] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    biometric_enabled: Optional[bool] = None
    notifications_enabled: Optional[bool] = None


# ============================================
# MODELOS DE SESIONES
# ============================================

class SessionResponse(BaseModel):
    """Modelo de respuesta para sesión activa"""
    id: str
    device_name: str
    device_type: str
    browser: str
    os: str
    ip_address: str
    location: str
    is_current: bool
    last_activity: str
    created_at: str


class LoginHistoryResponse(BaseModel):
    """Modelo de respuesta para historial de login"""
    id: str
    login_type: str
    ip_address: str
    device_name: str
    device_type: str
    browser: str
    os: str
    location: str
    status: str
    created_at: str


class SecurityChangeResponse(BaseModel):
    """Modelo de respuesta para cambios de seguridad"""
    id: str
    change_type: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    ip_address: str
    location: str
    status: str
    created_at: str


class ActivityLogResponse(BaseModel):
    """Modelo de respuesta para actividad del usuario"""
    id: str
    action: str
    details: Optional[dict] = None
    ip_address: str
    location: str
    status: str
    created_at: str


class SecurityStatsResponse(BaseModel):
    """Modelo de estadísticas de seguridad"""
    total_logins: int
    unique_devices: int
    last_login: Optional[dict] = None
    security_score: int
    recommendations: list[str]


# ============================================
# MODELOS DE WEBAUTHN (PASSKEYS)
# ============================================

class PasskeyCredentialResponse(BaseModel):
    """Modelo de respuesta para credenciales Passkey"""
    id: str
    name: str
    createdAt: str
    lastUsedAt: str


class WebAuthnRegistrationBeginResponse(BaseModel):
    """Respuesta para inicio de registro WebAuthn"""
    publicKey: dict


class WebAuthnRegistrationCompleteRequest(BaseModel):
    """Solicitud para completar registro WebAuthn"""
    id: str
    type: str
    response: dict


class WebAuthnLoginBeginRequest(BaseModel):
    """Solicitud para inicio de autenticación WebAuthn"""
    email: str


class WebAuthnLoginBeginResponse(BaseModel):
    """Respuesta para inicio de autenticación WebAuthn"""
    publicKey: dict


class WebAuthnLoginCompleteRequest(BaseModel):
    """Solicitud para completar autenticación WebAuthn"""
    id: str
    type: str
    response: dict


# ============================================
# MODELOS DE NOTIFICACIONES
# ============================================

class NotificationResponse(BaseModel):
    """Modelo de respuesta para notificaciones"""
    id: str
    type: str
    title: str
    message: str
    data: Optional[dict] = None
    read: bool = False
    created_at: str


# ============================================
# MODELOS DE ADMINISTRACIÓN
# ============================================

class AdminUserUpdate(BaseModel):
    """Modelo para que admin actualice usuarios"""
    role: Optional[str] = None
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


class AdminUserResponse(BaseModel):
    """Respuesta para admin sobre usuarios"""
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    created_at: Optional[str] = None
    last_login: Optional[str] = None