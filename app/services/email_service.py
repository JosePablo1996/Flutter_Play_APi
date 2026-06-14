import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv

load_dotenv()

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL", "noreply@mibilletera.com")
FROM_NAME = os.getenv("SENDGRID_FROM_NAME", "Mi Billetera")

class EmailService:
    @staticmethod
    async def send_otp_email(to_email: str, otp_code: str, name: str = None):
        """Send OTP code for password recovery"""
        
        subject = "Password Recovery - Mi Billetera"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0A0A0A;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 500px;
                    margin: 0 auto;
                    background: linear-gradient(135deg, #1A1A1A 0%, #0D0D0D 100%);
                    border-radius: 20px;
                    overflow: hidden;
                    box-shadow: 0 0 30px rgba(255,23,68,0.2);
                }}
                .header {{
                    background: linear-gradient(135deg, #FF1744, #00E676);
                    padding: 30px 20px;
                    text-align: center;
                }}
                .header h1 {{
                    color: white;
                    margin: 0;
                    font-size: 28px;
                    font-weight: bold;
                }}
                .content {{
                    padding: 30px;
                    text-align: center;
                }}
                .otp-code {{
                    background: linear-gradient(135deg, #FF1744, #00E676);
                    padding: 15px 30px;
                    border-radius: 12px;
                    display: inline-block;
                    margin: 20px 0;
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 5px;
                    color: white;
                    font-family: monospace;
                }}
                .message {{
                    color: #ffffff;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 20px 0;
                }}
                .footer {{
                    background-color: #0A0A0A;
                    padding: 20px;
                    text-align: center;
                    border-top: 1px solid rgba(255,255,255,0.1);
                }}
                .footer p {{
                    color: rgba(255,255,255,0.5);
                    font-size: 12px;
                    margin: 5px 0;
                }}
                .warning {{
                    background-color: rgba(255,23,68,0.1);
                    border-left: 4px solid #FF1744;
                    padding: 12px;
                    margin-top: 20px;
                    font-size: 12px;
                    color: rgba(255,255,255,0.7);
                    border-radius: 8px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Mi Billetera</h1>
                </div>
                <div class="content">
                    <p class="message">
                        Hola {name or 'usuario'},<br><br>
                        Hemos recibido una solicitud para restablecer tu contrasena.
                        Utiliza el siguiente codigo para completar el proceso:
                    </p>
                    <div class="otp-code">
                        {otp_code}
                    </div>
                    <p class="message">
                        Este codigo es valido por <strong>10 minutos</strong>.
                    </p>
                    <div class="warning">
                        Si no solicitaste este cambio, ignora este correo.
                        Tu cuenta permanece segura.
                    </div>
                </div>
                <div class="footer">
                    <p>Mi Billetera - University Banking</p>
                    <p>(c) 2024 Todos los derechos reservados</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_text_content = f"""
        Mi Billetera - Recuperacion de Contrasena
        
        Hola {name or 'usuario'},
        
        Has solicitado restablecer tu contrasena.
        Tu codigo de verificacion es: {otp_code}
        
        Este codigo es valido por 10 minutos.
        
        Si no solicitaste este cambio, ignora este correo.
        
        ---
        Mi Billetera - University Banking
        """
        
        try:
            message = Mail(
                from_email=(FROM_EMAIL, FROM_NAME),
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
                plain_text_content=plain_text_content
            )
            
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            
            print(f"Email sent to {to_email}. Status: {response.status_code}")
            return True
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return False

    @staticmethod
    async def send_login_otp_email(to_email: str, otp_code: str, name: str = None):
        """Send OTP code for passwordless login"""
        
        subject = "Access Code - Mi Billetera"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0A0A0A;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 500px;
                    margin: 0 auto;
                    background: linear-gradient(135deg, #1A1A1A 0%, #0D0D0D 100%);
                    border-radius: 20px;
                    overflow: hidden;
                    box-shadow: 0 0 30px rgba(0,230,118,0.2);
                }}
                .header {{
                    background: linear-gradient(135deg, #00E676, #2979FF);
                    padding: 30px 20px;
                    text-align: center;
                }}
                .header h1 {{
                    color: white;
                    margin: 0;
                    font-size: 28px;
                    font-weight: bold;
                }}
                .content {{
                    padding: 30px;
                    text-align: center;
                }}
                .otp-code {{
                    background: linear-gradient(135deg, #00E676, #2979FF);
                    padding: 15px 30px;
                    border-radius: 12px;
                    display: inline-block;
                    margin: 20px 0;
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 5px;
                    color: white;
                    font-family: monospace;
                    box-shadow: 0 0 20px rgba(0,230,118,0.4);
                }}
                .message {{
                    color: #ffffff;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 20px 0;
                }}
                .info {{
                    background-color: rgba(0,230,118,0.1);
                    border-left: 4px solid #00E676;
                    padding: 12px;
                    margin-top: 20px;
                    font-size: 12px;
                    color: rgba(255,255,255,0.7);
                    border-radius: 8px;
                }}
                .footer {{
                    background-color: #0A0A0A;
                    padding: 20px;
                    text-align: center;
                    border-top: 1px solid rgba(255,255,255,0.1);
                }}
                .footer p {{
                    color: rgba(255,255,255,0.5);
                    font-size: 12px;
                    margin: 5px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Mi Billetera</h1>
                </div>
                <div class="content">
                    <p class="message">
                        Hola {name or 'usuario'},<br><br>
                        Has solicitado <strong>iniciar sesion en Mi Billetera</strong>.
                        Utiliza el siguiente codigo para acceder a tu cuenta:
                    </p>
                    <div class="otp-code">
                        {otp_code}
                    </div>
                    <p class="message">
                        Este codigo es valido por <strong>10 minutos</strong> y es de un solo uso.
                    </p>
                    <div class="info">
                        Si no solicitaste este acceso, ignora este correo.
                        Tu cuenta permanece segura.
                    </div>
                </div>
                <div class="footer">
                    <p>Mi Billetera - University Banking</p>
                    <p>(c) 2024 Todos los derechos reservados</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_text_content = f"""
        Mi Billetera - Codigo de Acceso
        
        Hola {name or 'usuario'},
        
        Has solicitado iniciar sesion en Mi Billetera.
        Tu codigo de verificacion es: {otp_code}
        
        Este codigo es valido por 10 minutos y es de un solo uso.
        
        Si no solicitaste este acceso, ignora este correo.
        
        ---
        Mi Billetera - University Banking
        """
        
        try:
            message = Mail(
                from_email=(FROM_EMAIL, FROM_NAME),
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
                plain_text_content=plain_text_content
            )
            
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            
            print(f"Login OTP email sent to {to_email}. Status: {response.status_code}")
            return True
        except Exception as e:
            print(f"Error sending login OTP email: {str(e)}")
            return False

    # ============================================
    # ALERTAS DE SEGURIDAD
    # ============================================

    @staticmethod
    async def send_security_alert_email(
        to_email: str, 
        alert_type: str, 
        details: dict,
        name: str = None
    ):
        """
        Send security alert email.
        
        Alert types:
        - password_change: Password change
        - 2fa_enable: 2FA activation
        - 2fa_disable: 2FA deactivation
        - new_login: New login from unknown device
        - session_revoked: Session closed remotely
        """
        
        subject = f"Security Alert - {alert_type.replace('_', ' ').title()} - Mi Billetera"
        
        # Configuration by alert type
        alert_config = {
            "password_change": {
                "title": "Password Changed",
                "color": "#FF1744",
                "icon": "??",
                "message": "Your account password has been changed."
            },
            "2fa_enable": {
                "title": "Two-Factor Authentication Activated",
                "color": "#00E676",
                "icon": "???",
                "message": "Two-factor authentication has been activated on your account."
            },
            "2fa_disable": {
                "title": "Two-Factor Authentication Deactivated",
                "color": "#FF1744",
                "icon": "??",
                "message": "Two-factor authentication has been deactivated on your account."
            },
            "new_login": {
                "title": "New Login Detected",
                "color": "#2979FF",
                "icon": "??",
                "message": "A new login has been detected on your account."
            },
            "session_revoked": {
                "title": "Session Closed Remotely",
                "color": "#FF9800",
                "icon": "??",
                "message": "A remote session has been closed on your account."
            }
        }
        
        config = alert_config.get(alert_type, {
            "title": "Security Alert",
            "color": "#FF1744",
            "icon": "??",
            "message": "Activity has been detected on your account."
        })
        
        # Build additional details
        details_html = ""
        if details:
            details_html = "<div style='margin-top: 20px; padding: 15px; background-color: #1A1A1A; border-radius: 12px;'>"
            details_html += "<h3 style='margin: 0 0 10px 0; color: #ffffff; font-size: 14px;'>Details:</h3>"
            details_html += "<table style='width: 100%; font-size: 12px; color: #94a3b8;'>"
            for key, value in details.items():
                if value:
                    details_html += f"<tr><td style='padding: 4px 0;'><strong>{key.replace('_', ' ').title()}:</strong></td><td style='padding: 4px 0; text-align: right;'>{value}</td></tr>"
            details_html += "</table></div>"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0A0A0A;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 500px;
                    margin: 0 auto;
                    background: linear-gradient(135deg, #1A1A1A 0%, #0D0D0D 100%);
                    border-radius: 20px;
                    overflow: hidden;
                    box-shadow: 0 0 30px rgba(255,23,68,0.2);
                }}
                .header {{
                    background: linear-gradient(135deg, {config['color']}, {config['color']}80);
                    padding: 30px 20px;
                    text-align: center;
                }}
                .header h1 {{
                    color: white;
                    margin: 0;
                    font-size: 28px;
                    font-weight: bold;
                }}
                .header .icon {{
                    font-size: 48px;
                    margin-bottom: 10px;
                }}
                .content {{
                    padding: 30px;
                }}
                .alert-title {{
                    color: {config['color']};
                    font-size: 20px;
                    font-weight: bold;
                    margin: 0 0 10px 0;
                    text-align: center;
                }}
                .message {{
                    color: #ffffff;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 20px 0;
                    text-align: center;
                }}
                .warning {{
                    background-color: rgba(255,23,68,0.1);
                    border-left: 4px solid {config['color']};
                    padding: 12px;
                    margin-top: 20px;
                    font-size: 12px;
                    color: rgba(255,255,255,0.7);
                    border-radius: 8px;
                }}
                .footer {{
                    background-color: #0A0A0A;
                    padding: 20px;
                    text-align: center;
                    border-top: 1px solid rgba(255,255,255,0.1);
                }}
                .footer p {{
                    color: rgba(255,255,255,0.5);
                    font-size: 12px;
                    margin: 5px 0;
                }}
                .button {{
                    display: inline-block;
                    background: linear-gradient(135deg, {config['color']}, {config['color']}80);
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 8px;
                    margin-top: 20px;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="icon">{config['icon']}</div>
                    <h1>Mi Billetera</h1>
                </div>
                <div class="content">
                    <h2 class="alert-title">{config['title']}</h2>
                    <p class="message">
                        Hola {name or 'usuario'},<br><br>
                        {config['message']}
                    </p>
                    {details_html}
                    <div class="warning">
                        If you did not perform this action, <strong>contact support immediately</strong>.
                        Your account may be at risk.
                    </div>
                    <div style="text-align: center;">
                        <a href="https://mibilletera.com/security" class="button">Check my security</a>
                    </div>
                </div>
                <div class="footer">
                    <p>Mi Billetera - University Banking</p>
                    <p>(c) 2024 All rights reserved</p>
                    <p style="font-size: 10px;">This is an automated email, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_text_content = f"""
        Mi Billetera - Security Alert
        
        {config['title']}
        
        Hola {name or 'usuario'},
        
        {config['message']}
        
        Details:
        {chr(10).join([f"- {k.replace('_', ' ').title()}: {v}" for k, v in details.items() if v])}
        
        If you did not perform this action, contact support immediately.
        
        ---
        Mi Billetera - University Banking
        """
        
        try:
            message = Mail(
                from_email=(FROM_EMAIL, FROM_NAME),
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
                plain_text_content=plain_text_content
            )
            
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            
            print(f"Security alert email sent to {to_email}. Type: {alert_type}. Status: {response.status_code}")
            return True
        except Exception as e:
            print(f"Error sending security alert email: {str(e)}")
            return False

    @staticmethod
    async def send_new_device_alert(to_email: str, device_info: dict, name: str = None):
        """
        Send alert when a new device is detected.
        Especially useful for suspicious logins.
        """
        
        subject = "New Device Detected - Mi Billetera"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0A0A0A;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 500px;
                    margin: 0 auto;
                    background: linear-gradient(135deg, #1A1A1A 0%, #0D0D0D 100%);
                    border-radius: 20px;
                    overflow: hidden;
                    box-shadow: 0 0 30px rgba(41,121,255,0.2);
                }}
                .header {{
                    background: linear-gradient(135deg, #2979FF, #00E676);
                    padding: 30px 20px;
                    text-align: center;
                }}
                .header h1 {{
                    color: white;
                    margin: 0;
                    font-size: 28px;
                    font-weight: bold;
                }}
                .content {{
                    padding: 30px;
                }}
                .device-card {{
                    background-color: #1A1A1A;
                    border-radius: 12px;
                    padding: 20px;
                    margin: 20px 0;
                }}
                .device-card p {{
                    margin: 8px 0;
                }}
                .warning {{
                    background-color: rgba(255,23,68,0.1);
                    border-left: 4px solid #FF1744;
                    padding: 12px;
                    margin-top: 20px;
                    font-size: 12px;
                    color: rgba(255,255,255,0.7);
                    border-radius: 8px;
                }}
                .footer {{
                    background-color: #0A0A0A;
                    padding: 20px;
                    text-align: center;
                    border-top: 1px solid rgba(255,255,255,0.1);
                }}
                .button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #2979FF, #00E676);
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 8px;
                    margin-top: 20px;
                    font-size: 14px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Mi Billetera</h1>
                </div>
                <div class="content">
                    <h2 style="color: #FF9800; text-align: center;">New Device Detected</h2>
                    <p style="color: #ffffff; text-align: center;">
                        Hola {name or 'usuario'},<br><br>
                        A login from a new device has been detected.
                    </p>
                    <div class="device-card">
                        <h3 style="color: #ffffff; margin: 0 0 10px 0;">Device Details:</h3>
                        <p><strong>Device:</strong> {device_info.get('device_name', 'Unknown')}</p>
                        <p><strong>Type:</strong> {device_info.get('device_type', 'Unknown')}</p>
                        <p><strong>Browser:</strong> {device_info.get('browser', 'Unknown')}</p>
                        <p><strong>OS:</strong> {device_info.get('os', 'Unknown')}</p>
                        <p><strong>IP Address:</strong> {device_info.get('ip_address', 'Unknown')}</p>
                        <p><strong>Date and Time:</strong> {device_info.get('timestamp', 'Unknown')}</p>
                    </div>
                    <div class="warning">
                        <strong>Wasn't you?</strong> If you don't recognize this device,
                        we recommend closing the session remotely and changing your password immediately.
                    </div>
                    <div style="text-align: center;">
                        <a href="https://mibilletera.com/security/sessions" class="button">View my active sessions</a>
                    </div>
                </div>
                <div class="footer">
                    <p>Mi Billetera - University Banking</p>
                    <p>(c) 2024 All rights reserved</p>
                </div>
            </div>
        </html>
        """
        
        try:
            message = Mail(
                from_email=(FROM_EMAIL, FROM_NAME),
                to_emails=to_email,
                subject=subject,
                html_content=html_content,
                plain_text_content=f"""
                Mi Billetera - New Device Detected
                
                Hola {name or 'usuario'},
                
                A login from a new device has been detected.
                
                Details:
                - Device: {device_info.get('device_name', 'Unknown')}
                - Type: {device_info.get('device_type', 'Unknown')}
                - Browser: {device_info.get('browser', 'Unknown')}
                - OS: {device_info.get('os', 'Unknown')}
                - IP: {device_info.get('ip_address', 'Unknown')}
                - Date: {device_info.get('timestamp', 'Unknown')}
                
                Wasn't you? Log in to your account and check your active sessions.
                
                ---
                Mi Billetera - University Banking
                """
            )
            
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            response = sg.send(message)
            
            print(f"New device alert sent to {to_email}. Status: {response.status_code}")
            return True
        except Exception as e:
            print(f"Error sending new device alert: {str(e)}")
            return False