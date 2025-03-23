import MongoStore from 'connect-mongo';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import session from 'express-session';
import sharedSession from 'express-socket.io-session';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors'; // <- Añadido
import User from './models/User.js'; // <- Añadido (¡verifica la ruta!)
import Message from './models/Message.js'; // <- Añadido

// =============================================
//           CONFIGURACIÓN DE SESIÓN
// =============================================
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGODB_URI, // Usa tu variable de entorno
    ttl: 86400 // Sesiones expiran en 1 día
  }),
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
});

// =============================================
//          CONEXIÓN A MONGODB ATLAS
// =============================================
mongoose.connect(process.env.MONGODB_URI) // <- Cambiado a MONGO_URI
  .then(() => console.log('🟢 Conectado a MongoDB Atlas'))
  .catch(err => {
    console.error('🔴 Error de conexión:', err);
    process.exit(1);
  });

// =============================================
//          INICIALIZACIÓN DEL SERVIDOR
// =============================================
const app = express();
const server = http.createServer(app);

// Configuración CORS para Express
app.use(cors({
  origin: "https://chatus-production.up.railway.app",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true // <- Permite cookies
  
}));

// Configuración Socket.IO
const io = new Server(server, {
  cors: {
    origin: "https://chatus-production.up.railway.app",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Antes de los middlewares:
app.set('trust proxy', 1); // Confía en el proxy de Railway

// Modifica el rate limiter:
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  validate: { trustProxy: true } // ✅ Considera IPs reales
}));

// =============================================
//               MIDDLEWARES
// =============================================

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(), // Mantener políticas por defecto
        "script-src": ["'self'", "'unsafe-inline'"], // Permitir scripts inline
        "script-src-attr": ["'self'", "'unsafe-inline'"] // Permitir event handlers
      }
    },
    crossOriginEmbedderPolicy: false // Necesario para Socket.IO
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(sessionMiddleware);

// Rate Limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

io.use(sharedSession(sessionMiddleware, { autoSave: true }));

// =============================================
//            RUTAS DE AUTENTICACIÓN (Actualizadas)
// =============================================
app.post('/register', async (req, res) => {
  try {
    console.log("Intento de registro:", req.body); // <- Debug
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const user = new User({ username, password });
    await user.save();
    
    res.status(201).json({ message: '✅ Usuario registrado' });
  } catch (error) {
    console.error("Error en registro:", error); // <- Log detallado
    res.status(500).json({ error: 'Error al registrar' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    req.session.userId = user._id;
    res.json({ message: '🎉 Login exitoso', username: user.username });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.post('/change-password', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'No autorizado' });
  
  const { currentPassword, newPassword } = req.body;
  try {
    const user = await User.findById(req.session.userId);
    
    // Usa el método del modelo para comparar contraseñas
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }
    
    // Asigna la nueva contraseña en texto plano (el pre-save hook la hasheará)
    user.password = newPassword;
    await user.save();
    
    // Destruye la sesión para forzar re-login
    req.session.destroy();
    
    res.json({ message: '✅ Contraseña actualizada. Vuelve a iniciar sesión' });
    
  } catch (error) {
    console.error("Error en cambio de contraseña:", error);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});


app.post('/change-username', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'No autorizado' });

  const { newUsername } = req.body;
  try {
    // Verificar si el nombre ya existe
    const existingUser = await User.findOne({ username: newUsername });
    if (existingUser) {
      return res.status(400).json({ error: 'El nombre ya está en uso' });
    }

    // Verifica que el nombre sea de al menos 3 caracteres.
    if (newUsername.length < 3) {
      return res.status(400).json({ error: 'Mínimo 3 caracteres' });
    }

    // Actualizar nombre
    await User.findByIdAndUpdate(req.session.userId, { 
      username: newUsername 
    });

    res.json({ message: '✅ Nombre actualizado' });
    
  } catch (error) {
    console.error("Error al cambiar nombre:", error);
    res.status(500).json({ error: 'Error al actualizar nombre' });
  }
});


app.post('/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200);
});

app.get('/check-auth', (req, res) => {
  res.status(req.session.userId ? 200 : 401).json({
    isAuthenticated: !!req.session.userId,
    userId: req.session.userId
  });
});

// =============================================
//              SOCKET.IO (CHAT)
// =============================================
io.on('connection', (socket) => {
  if (!socket.handshake.session.userId) {
    socket.disconnect();
    return;
  }

  console.log(`✅ Usuario conectado: ${socket.handshake.session.userId}`);

  socket.on('chat message', async (msg) => {
    try {
      const user = await User.findById(socket.handshake.session.userId);
      const sanitizedMsg = escapeHTML(msg);

      const newMessage = new Message({
        user: user._id,
        text: sanitizedMsg
      });

      await newMessage.save();
      io.emit('chat message', {
        uid: user._id,
        user: user.username,
        text: sanitizedMsg
      });

    } catch (error) {
      console.error('🔥 Error al guardar mensaje:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log(`❌ Usuario desconectado: ${socket.handshake.session.userId}`);
  });
});

// =============================================
//            FUNCIÓN DE SEGURIDAD
// =============================================
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// =============================================
//               INICIAR SERVIDOR
// =============================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Servidor en http://localhost:${PORT}`);
});
