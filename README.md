# Chatus - Chat en Tiempo Real (React + Supabase + Node.js/Socket.IO)

## Descripción
Chatus es una aplicación de chat en tiempo real que permite a los usuarios registrarse, iniciar sesión, chatear, y administrar mensajes. El proyecto está construido con React en el frontend, Supabase como backend de autenticación y base de datos, y Node.js/Socket.IO para la comunicación en tiempo real.

---

## Componentes del Proyecto
- **frontend/**: Aplicación React (componentes: Auth, Chat, Profile, ResetPassword, etc.)
- **backend/**: Servidor Node.js con Express y Socket.IO para la lógica de chat y autenticación de sockets.
- **INFO_SUPABASE.txt**: Archivo orientativo con la estructura y políticas de la base de datos. La configuración avanzada (migraciones, triggers, RLS, funciones) se gestiona directamente en la consola web de Supabase.

---

## Funcionalidad Principal
- Registro de usuarios con email y nombre de usuario único.
- Login por email o nombre de usuario.
- Recuperación de contraseña por email o usuario.
- Chat en tiempo real con mensajes instantáneos.
- Gestión de perfiles: edición de nombre de usuario y visualización de email.
- Administración: usuarios con rol admin pueden borrar todos los mensajes y resetear IDs.
- Tema oscuro global.
- Seguridad avanzada: RLS en Supabase, validaciones en frontend y backend.
- Reconexión automática y robusta ante desconexiones o cambios de pestaña.

---

## Funciones Implementadas
- Autenticación y registro seguro.
- Trigger automático en Supabase para crear perfiles al registrar usuario.
- Heartbeat de Socket.IO configurado para mantener la conexión viva.
- CORS en backend para desarrollo y producción.
- Eliminada lógica de creación manual de perfiles y temporizador de desconexión por inactividad.
- Políticas RLS revisadas y seguras.

---

## Tareas Pendientes / Mejoras Futuras
- Forzar limpieza de chat en todos los clientes cuando el admin borre todos los mensajes (broadcast robusto).
- Mejorar feedback visual y validaciones en el frontend.
- Añadir tests automáticos.
- Eliminar logs de backend para producción.
- Reimplementar el cambio de contraseña de forma segura.

---

## Errores Conocidos
Actualmente, no hay errores conocidos ni problemas críticos pendientes.

---

## Despliegue y Buenas Prácticas
- Backend desplegado en Render, frontend en Vercel.
- Variables de entorno configuradas en los servicios de despliegue.
- Archivos sensibles (`.env`, `.env.local`) están en `.gitignore` y no se suben a GitHub.
- Documentación de despliegue y seguridad disponible en `DEPLOYMENT_INSTRUCTIONS.txt` y `PROJECT_STATUS_AND_INFO.txt`.

---

## Contacto y Soporte
Para dudas técnicas, traspaso o soporte, consulta el documento `PROJECT_STATUS_AND_INFO.txt` para información de contacto y estado de claves/configuraciones.
