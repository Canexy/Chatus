
# Chatus - Chat en Tiempo Real (React + Supabase + Node.js/Socket.IO)

## Descripción
Chatus es una aplicación de chat en tiempo real que permite a los usuarios registrarse, iniciar sesión, chatear y administrar mensajes. El proyecto está construido con React en el frontend, Supabase como backend de autenticación y base de datos, y Node.js/Socket.IO para la comunicación en tiempo real.

---

## Componentes del Proyecto
- **frontend/**: Aplicación React (componentes: Auth, Chat, Profile, ResetPassword, etc.)
- **backend/**: Servidor Node.js con Express y Socket.IO para la lógica de chat y autenticación de sockets.

> Nota: La documentación avanzada de la base de datos, despliegue y estado del proyecto se gestiona como archivos personales y no está incluida en el repositorio público. Si necesitas detalles sobre migraciones, políticas RLS, instrucciones de despliegue o estado del proyecto, contacta con el responsable del repositorio.

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

---

## Contacto y Soporte
Para dudas técnicas, traspaso o soporte, contacta con el responsable del repositorio para obtener la documentación avanzada o instrucciones de despliegue.
