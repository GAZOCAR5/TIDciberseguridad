# TIDciberseguridad

## Descripción
Este es un sistema seguro de transmisión de datos de telemetría usando cifrado simétrico (AES-256 CBC) y autenticación HMAC-SHA256. Está diseñado para funcionar en dispositivos IoT o sistemas embebidos donde se requiere alta seguridad y bajo consumo. 

Los códigos presentados son la base del proyecto TID en el serverside (IoT)

## Componentes/Estructura

- **Cifrado AES-256 CBC** de los datos de telemetría
- **Firma HMAC-SHA256** para validar integridad
- **Handshake con RSA** para distribuir la clave AES de forma segura
- Validación de clientes mediante **fingerprint de clave pública**
- Acceso restringido a `/telemetria` solo para clientes autorizados
