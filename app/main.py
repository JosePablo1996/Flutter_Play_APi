from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import auth, expenses, profile, two_factor, sessions, webauthn, categories

# ============================================
# CONFIGURACION DE LA APLICACION
# ============================================

app = FastAPI(
    title="Flutter Play API - Banca Universitaria",
    description="""
    ## API para la aplicacion de billetera personal

    ### Caracteristicas principales:
    * **Autenticacion**: Registro, login tradicional, y login con OTP
    * **2FA**: Autenticacion de Dos Factores con Google Authenticator
    * **Passkeys**: Autenticacion biometrica con Windows Hello, Face ID, Touch ID
    * **Gestion de gastos**: CRUD completo de gastos
    * **Categorias**: Categorias predefinidas y personalizables
    * **Presupuestos**: Control de presupuestos por categoria
    * **Perfil de usuario**: Gestion de perfil con avatar y banner
    * **Estadisticas**: Analisis y reportes de gastos
    * **Seguridad**: Recuperacion de contrasena con OTP
    * **Sesiones activas**: Gestion de dispositivos conectados
    * **Historial de accesos**: Registro completo de inicios de sesion

    ### 🎯 Novedades v2.6.0:

    #### Passkey con registro completo
    - Los inicios de sesion con Passkey ahora se registran en `login_history` (tipo `passkey`)
    - Creacion automatica de sesiones en `user_sessions`
    - Registro de actividad en `activity_log`
    - Alertas por email para nuevos dispositivos

    #### Estadisticas de seguridad mejoradas
    - Nuevo campo `has_passkey` en `/sessions/security-stats`
    - Mayor puntuacion de seguridad para usuarios con Passkey (+20 puntos)
    - Recomendaciones personalizadas para mejorar la seguridad

    #### Mejoras en WebAuthn
    - Endpoint `/webauthn/login/begin-without-email` funcionando correctamente
    - Mejor manejo de errores en autenticacion biometrica

    ### Endpoints disponibles:

    #### Autenticacion (`/api/v1/auth`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | POST | `/auth/register` | Registrar nuevo usuario |
    | POST | `/auth/login` | Iniciar sesion con email/contrasena |
    | POST | `/auth/login-otp-request` | Solicitar codigo OTP |
    | POST | `/auth/login-with-otp` | Iniciar sesion con OTP |
    | POST | `/auth/request-otp` | Solicitar OTP para recuperacion |
    | POST | `/auth/verify-otp` | Verificar codigo OTP |
    | POST | `/auth/reset-password-with-otp` | Restablecer contrasena con OTP |
    | POST | `/auth/change-password` | Cambiar contrasena (requiere auth) |
    | GET | `/auth/me` | Obtener usuario actual |
    | POST | `/auth/logout` | Cerrar sesion |

    #### 2FA (`/api/v1/auth/2fa`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | POST | `/auth/2fa/setup` | Configurar 2FA (generar QR) |
    | POST | `/auth/2fa/verify` | Verificar y activar 2FA |
    | POST | `/auth/2fa/disable` | Desactivar 2FA |
    | GET | `/auth/2fa/status` | Obtener estado de 2FA |
    | POST | `/auth/2fa/verify-login` | Verificar durante login |

    #### Passkeys (`/api/v1/webauthn`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | POST | `/webauthn/register/begin` | Iniciar registro de passkey |
    | POST | `/webauthn/register/complete` | Completar registro de passkey |
    | POST | `/webauthn/login/begin` | Iniciar autenticacion con passkey |
    | POST | `/webauthn/login/begin-without-email` | Iniciar autenticacion sin email 🎯 |
    | POST | `/webauthn/login/complete` | Completar autenticacion con passkey |
    | GET | `/webauthn/credentials` | Listar passkeys del usuario |
    | GET | `/webauthn/status` | Obtener estado de passkeys 🎯 |
    | DELETE | `/webauthn/credentials/{id}` | Eliminar passkey |

    #### Gastos (`/api/v1/expenses`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | GET | `/expenses` | Listar todos los gastos |
    | POST | `/expenses` | Crear nuevo gasto |
    | PUT | `/expenses/{id}` | Actualizar gasto |
    | DELETE | `/expenses/{id}` | Eliminar gasto |
    | GET | `/expenses/stats` | Obtener estadisticas de gastos |

    #### Categorias (`/api/v1/categories`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | GET | `/categories` | Listar todas las categorias (default + personalizadas) |
    | GET | `/categories/default` | Listar solo categorias por defecto |
    | GET | `/categories/my` | Listar solo categorias personalizadas del usuario |
    | POST | `/categories` | Crear nueva categoria personalizada |
    | PUT | `/categories/{id}` | Actualizar categoria personalizada |
    | DELETE | `/categories/{id}` | Eliminar categoria personalizada |
    | POST | `/categories/ensure-default` | Forzar creacion de categorias por defecto |

    #### Presupuestos (`/api/v1/budgets`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | GET | `/budgets` | Listar presupuestos |
    | POST | `/budgets` | Crear presupuesto |
    | PUT | `/budgets/{category}` | Actualizar presupuesto por categoria |
    | DELETE | `/budgets/{category}` | Eliminar presupuesto |
    | GET | `/budgets/summary` | Obtener resumen de presupuestos |

    #### Perfil (`/api/v1/profile`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | GET | `/profile` | Obtener perfil del usuario |
    | PUT | `/profile` | Actualizar perfil del usuario |

    #### Sesiones (`/api/v1/sessions`)
    | Metodo | Endpoint | Descripcion |
    |--------|----------|-------------|
    | GET | `/sessions` | Listar sesiones activas |
    | POST | `/sessions/revoke` | Revocar sesion especifica |
    | POST | `/sessions/revoke-all` | Revocar todas las sesiones |
    | GET | `/sessions/activity` | Obtener historial de actividad |
    | GET | `/sessions/login-history` | Obtener historial de logins |
    | GET | `/sessions/security-changes` | Obtener cambios de seguridad |
    | GET | `/sessions/security-stats` | Obtener estadisticas de seguridad 🎯 |

    ### Autenticacion:
    La mayoria de los endpoints requieren un token JWT en el header:
    `Authorization: Bearer <token>`

    ### 🎯 Novedades de seguridad (v2.6.0):
    - **Registro completo de Passkey**: Ahora cada inicio de sesion con Passkey queda registrado
    - **Estadisticas mejoradas**: El endpoint `/security-stats` ahora incluye `has_passkey`
    - **Mejor puntuacion**: Los usuarios con Passkey obtienen +20 puntos en su puntuacion de seguridad
    """,
    version="2.6.0",
    contact={
        "name": "Soporte Flutter Play",
        "email": "soporte@flutterplay.com",
    },
    license_info={
        "name": "MIT",
    },
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ============================================
# CONFIGURACION CORS - CORREGIDA PARA PRODUCCION
# ============================================

# ✅ Lista de orígenes permitidos (CORS)
origins = [
    # Desarrollo local
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
    "http://localhost:4173",  # Vite preview
    # ✅ Producción - Frontend en Render
    "https://flutter-play-web.onrender.com",
    # ✅ La propia API
    "https://flutter-play-api.onrender.com",
    # ✅ Dominios personalizados (agregar si los tienes)
    # "https://flutterplay.com",
    # "https://www.flutterplay.com",
]

# ✅ Configuración CORS mejorada
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,              # Orígenes específicos
    allow_credentials=True,             # Permitir cookies/credenciales
    allow_methods=["*"],                # Permitir todos los métodos HTTP
    allow_headers=["*"],                # Permitir todos los headers
    expose_headers=[
        "Content-Type",
        "Authorization",
        "X-Request-ID",
        "X-Response-Time",
    ],                                   # Headers expuestos al cliente
    max_age=3600,                        # Cache de preflight (1 hora)
)

# ============================================
# INCLUIR ROUTERS CON PREFIJO /api/v1
# ============================================

API_PREFIX = "/api/v1"

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(expenses.router, prefix=API_PREFIX)
app.include_router(profile.router, prefix=API_PREFIX)
app.include_router(two_factor.router, prefix=API_PREFIX)
app.include_router(sessions.router, prefix=API_PREFIX)
app.include_router(webauthn.router, prefix=API_PREFIX)
app.include_router(categories.router, prefix=API_PREFIX)

# ============================================
# ENDPOINTS DE PRUEBA
# ============================================

@app.get("/", tags=["Status"])
async def root():
    """
    Estado de la API

    Verifica que el servicio este funcionando correctamente.
    """
    return {
        "message": "API de Flutter Play - Mi Banca Universitaria funcionando correctamente",
        "version": "2.6.0",
        "status": "online",
        "endpoints": {
            "auth": "/api/v1/auth",
            "expenses": "/api/v1/expenses",
            "categories": "/api/v1/categories",
            "budgets": "/api/v1/budgets",
            "profile": "/api/v1/profile",
            "sessions": "/api/v1/sessions",
            "webauthn": "/api/v1/webauthn",
            "docs": "/docs"
        }
    }


@app.get("/health", tags=["Status"])
async def health_check():
    """
    Health Check

    Endpoint para verificar el estado del servidor.
    """
    return {"status": "ok", "version": "2.6.0"}