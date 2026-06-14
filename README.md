# 🎓 Flutter Play API - Mi Banca Universitaria

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)
![SendGrid](https://img.shields.io/badge/SendGrid-00A9E0?style=for-the-badge&logo=sendgrid&logoColor=white)

## 📱 Descripción General

**Flutter Play API** es el backend robusto y seguro que potencia la aplicación **Flutter Play - Mi Banca Universitaria**, una plataforma diseñada específicamente para ayudar a estudiantes universitarios a gestionar sus finanzas personales de manera inteligente, segura y eficiente.

> 🚀 *"Tu banca universitaria, siempre contigo"*

## ✨ Características Principales

### 🔐 Autenticación y Seguridad
- **Login tradicional** con email/contraseña
- **Login sin contraseña** mediante código OTP (One-Time Password)
- **Autenticación Biométrica** (WebAuthn/Passkeys) - Windows Hello, Face ID, Touch ID
- **Autenticación de Dos Factores (2FA)** con Google Authenticator, Authy o Microsoft Authenticator
- **Códigos de respaldo** (10 códigos de un solo uso)
- **Historial de contraseñas** - Previene reutilización de las últimas 5 contraseñas
- **JWT Tokens** con soporte HS256 y ES256

### 💰 Gestión Financiera
- **CRUD completo de gastos** - Crear, leer, actualizar, eliminar
- **Categorías personalizables** - 8 categorías predefinidas + categorías personalizadas
- **Gastos recurrentes** - Configuración diaria, semanal, mensual o anual
- **Presupuestos inteligentes** - Alertas automáticas al alcanzar el 70% y 100% del límite
- **Estadísticas avanzadas** - Filtros por fecha y categoría

### 📊 Dashboard y Visualización
- **Gráficos interactivos** - Barras, pastel, área y tendencias
- **Calendario de gastos** - Visualización de gastos por día
- **Exportación de datos** - Formatos CSV y JSON

### 👤 Perfil de Usuario
- **Avatar y banner personalizables** - Subida de imágenes a Supabase Storage
- **Configuración de moneda** - USD, EUR, MXN, COP, ARS, CLP, PEN, GTQ
- **Presupuesto mensual** - Control financiero personalizado

### 🔒 Gestión de Sesiones
- **Sesiones activas** - Visualiza todos tus dispositivos conectados
- **Revocación de sesiones** - Cierre remoto de sesiones individuales
- **Cierre masivo** - Opción "Cerrar todas las sesiones"
- **Historial de accesos** - Registro completo de inicios de sesión
- **Cambios de seguridad** - Auditoría de cambios de contraseña y 2FA

### 📧 Notificaciones y Alertas
- **Alertas por email** - Nuevos dispositivos detectados
- **Cambios de seguridad** - Contraseña actualizada, 2FA activado/desactivado
- **Códigos OTP** - Recuperación de contraseña y login sin contraseña

## 🛠️ Stack Tecnológico

### Backend Core
| Tecnología | Versión | Descripción |
|------------|---------|-------------|
| **FastAPI** | 0.115.6 | Framework web asíncrono de alto rendimiento |
| **Python** | 3.11+ | Lenguaje principal |
| **Uvicorn** | 0.34.0 | Servidor ASGI |

### Base de Datos
| Tecnología | Descripción |
|------------|-------------|
| **Supabase** | Backend como servicio (PostgreSQL + Auth + Storage) |
| **PostgreSQL** | Base de datos relacional |
| **SQLAlchemy** | ORM (opcional, consultas directas) |

### Seguridad
| Tecnología | Descripción |
|------------|-------------|
| **python-jose** | JWT tokens (HS256/ES256) |
| **passlib[bcrypt]** | Hashing de contraseñas |
| **pyotp** | Generación/verificación de códigos TOTP para 2FA |
| **qrcode** | Generación de códigos QR para 2FA |
| **WebAuthn** | Passkeys y autenticación biométrica |

### Email
| Tecnología | Descripción |
|------------|-------------|
| **SendGrid** | Envío de emails transaccionales |

## 📁 Estructura del Proyecto

backend/
├── app/
│ ├── routers/
│ │ ├── auth.py # Autenticación, login, OTP
│ │ ├── two_factor.py # 2FA TOTP
│ │ ├── webauthn.py # Passkeys biométricos
│ │ ├── sessions.py # Sesiones activas y revocación
│ │ ├── expenses.py # CRUD de gastos
│ │ ├── categories.py # Categorías de gastos
│ │ ├── budgets.py # Presupuestos
│ │ └── profile.py # Perfil de usuario
│ ├── services/
│ │ ├── email_service.py # Envío de emails
│ │ └── device_alert.py # Alertas de nuevos dispositivos
│ ├── models.py # Modelos Pydantic
│ ├── auth.py # Utilidades de autenticación
│ ├── auth_utils.py # Helpers de JWT
│ ├── database.py # Clientes Supabase
│ └── main.py # Punto de entrada
├── requirements.txt # Dependencias
└── .env # Variables de entorno


## 🔧 Instalación y Configuración

### 1. Clonar el repositorio
```bash
git clone https://github.com/JosePablo1996/flutter-play-api.git
cd flutter-play-api/backend

2. Crear entorno virtual

# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate

3. Instalar dependencias

pip install -r requirements.txt

4. Configurar variables de entorno

Crea un archivo .env en la raíz del backend:

# Supabase Configuration
SUPABASE_URL=tu_url_supabase
SUPABASE_ANON_KEY=tu_anon_key
SUPABASE_SERVICE_KEY=tu_service_key
JWT_SECRET=tu_secret_key

# SendGrid Configuration
SENDGRID_API_KEY=tu_api_key
SENDGRID_FROM_EMAIL=noreply@tudominio.com
SENDGRID_FROM_NAME="Flutter Play"

5. Ejecutar el servidor

uvicorn app.main:app --reload --port 8000

6. Acceder a la documentación interactiva

    Swagger UI: http://localhost:8000/docs
	
                          📡 Endpoints Principales
Método	           Endpoint	                           Descripción
POST	   /api/v1/auth/register	                   Registrar usuario
POST	   /api/v1/auth/login	                        Iniciar sesión
POST	  /api/v1/auth/login-otp-request	          Solicitar código OTP
POST	   /api/v1/auth/login-with-otp	            Iniciar sesión con OTP
POST	     /api/v1/auth/2fa/setup	                    Configurar 2FA
POST	   /api/v1/auth/2fa/verify-login	             Verificar 2FA
GET	           /api/v1/expenses	                         Listar gastos
GET	          /api/v1/categories	                     Listar categorías
GET	          /api/v1/budgets/summary	              Resumen de presupuestos
GET	            /api/v1/sessions	                     Sesiones activas
POST	    /api/v1/sessions/revoke-all	            Cerrar todas las sesiones


🔐 Flujos de Autenticación
1. Login tradicional con 2FA

Email/Password → Verificar 2FA → JWT Token → Acceso

2. Login sin contraseña (OTP)

Email → Código OTP → Verificar 2FA (opcional) → JWT Token → Acceso

3. Login biométrico (Passkey)

Windows Hello/Face ID/Touch ID → Verificar Passkey → JWT Token → Acceso


             📊 Base de Datos - Tablas Principales
Tabla	                                                    Descripción

profiles	        ---------------------  Perfiles de usuario (incluye avatar, banner, role)
expenses	        ---------------------             Gastos registrados
categories	        ---------------------    Categorías (predefinidas + personalizadas)
budgets	            ---------------------         Presupuestos por categoría
user_sessions       ---------------------	          Sesiones activas
login_history       --------------------- 	   Historial de inicios de sesión
security_changes    ---------------------	        Cambios de seguridad
password_history    --------------------- 	      Historial de contraseñas
passkeys	        ---------------------           Credenciales WebAuthn                

                 👨‍💻 Autor

        José Pablo Miranda Quintanilla

    .GitHub: @JosePablo1996

    .Email: pabloboquintanilla988@gmail.com    
	
	📄 Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo LICENSE para más información.

🌟 Si te gusta este proyecto, no olvides darle una estrella en GitHub 🌟

Flutter Play - Tu banca universitaria, siempre contigo

