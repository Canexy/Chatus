# Chatus - Chat en tiempo real (React + Supabase + Node.js)

## ¿Qué es Chatus?
Chatus es una aplicación de chat en tiempo real con autenticación, administración y control de mensajes, desarrollada con React (frontend), Supabase (backend y base de datos) y Node.js/Socket.IO (servidor de sockets).

---

## Funcionalidades actuales
- **Registro y login** usando email o nombre de usuario.
- **Recuperación de contraseña** usando email o nombre de usuario.
- **Cambio de nombre de usuario** desde el perfil (con avisos y validaciones).
- **Tema oscuro global** y experiencia de usuario moderna.
- **Chat en tiempo real** con reconexión automática y mensajes de estado.
- **Menú de administración** solo visible para usuarios admin (`is_admin` en `profiles`).
- **Función admin:** borrar todos los mensajes y resetear IDs (seguro, solo admin).
- **Políticas RLS** en Supabase para máxima seguridad (cada usuario solo puede ver/editar su perfil y mensajes; login por usuario seguro).
- **Creación automática de perfil tras confirmación de email**.
- **Logs de backend activos para depuración**.

---

## Pendiente / To Do
- Forzar limpieza de chat en todos los clientes cuando el admin borre todos los mensajes (de forma robusta).
- Reimplementar la funcionalidad de cambio de contraseña de forma segura y funcional.
- Mejorar feedback visual, validaciones y tests automáticos.
- Eliminar logs de backend para producción cuando ya no sean necesarios.

---

## ¿Qué diferencia este README del de `frontend/`?
- **Este README** describe el proyecto completo, sus funcionalidades, arquitectura y estado general.
- **El README de `frontend/`** solo contiene instrucciones técnicas para ejecutar el frontend (React) y scripts de desarrollo.

---

## Estructura del proyecto
- `frontend/` - React app (interfaz de usuario)
- `backend/` - Servidor Node.js/Socket.IO

---

## Requisitos
- Node.js, npm
- Cuenta y proyecto en Supabase

---

## Contacto
Desarrollado por Mario. Para dudas o mejoras, abre un issue o contacta directamente.
