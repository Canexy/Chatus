import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import session from 'express-session';
import sharedSession from 'express-socket.io-session';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

// =============================================
//           CONFIGURACIÓN DE SESIÓN
// =============================================
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
});

// =============================================
//          CONEXIÓN A MONGODB ATLAS
// =============================================
mongoose.connect(process.env.MONGODB_URI)
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
const io = new Server(server, {
  cors: {
    origin: "https://chatus-production.up.railway.app/",
    methods: ["GET", "POST"]
  }
});

// =============================================
//               MIDDLEWARES
// =============================================
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(sessionMiddleware);

// Rate Limiting (100 peticiones/15min por IP)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

io.use(sharedSession(sessionMiddleware, { autoSave: true }));

// =============================================
//            RUTAS DE AUTENTICACIÓN
// =============================================
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: '✅ Usuario registrado' });
  } catch (error) {
    res.status(400).json({ error: error.code === 11000 ? 'El usuario ya existe' : 'Error al registrar' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: '🔐 Credenciales inválidas' });
    }

    req.session.userId = user._id;
    res.json({ message: '🎉 Login exitoso', username: user.username });
  } catch (error) {
    res.status(500).json({ error: '🚨 Error en el servidor' });
  }
});

app.post('/change-password', async (req, res) => {
  if (!req.session.userId) return res.status(401).send('No autorizado');
  
  const { currentPassword, newPassword } = req.body;
  try {
    const user = await User.findById(req.session.userId);
    if (!await bcrypt.compare(currentPassword, user.password)) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }
    
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: '✅ Contraseña actualizada' });
  } catch (error) {
    res.status(500).json({ error: '🚨 Error al cambiar contraseña' });
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

  const userId = socket.handshake.session.userId;
  console.log(`✅ Usuario conectado: ${userId}`);

  // Manejar nuevos mensajes
  socket.on('chat message', async (msg) => {
    try {
      const user = await User.findById(userId);
      const sanitizedMsg = escapeHTML(msg);

      const newMessage = new Message({
        user: userId,
        text: sanitizedMsg
      });

      await newMessage.save();
      
      // Limitar a 50 mensajes
      const totalMessages = await Message.countDocuments();
      if (totalMessages > 50) {
        const oldestMessages = await Message.find().sort({ _id: 1 }).limit(totalMessages - 50);
        await Message.deleteMany({ _id: { $in: oldestMessages.map(m => m._id) } });
      }

      io.emit('chat message', {
        uid: userId,
        user: user.username,
        text: sanitizedMsg
      });

    } catch (error) {
      console.error('🔥 Error al guardar mensaje:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log(`❌ Usuario desconectado: ${userId}`);
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
