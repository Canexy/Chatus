require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createServer } = require('http');
const { Server } = require('socket.io');
const supabase = require('@supabase/supabase-js').createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const app = express();
app.use(cors());
app.get('/ping', (req, res) => res.send('pong'));

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ["http://localhost:3000", "https://chatus-one.vercel.app"],
    methods: ["GET", "POST"],
    credentials: true
  },
  // Heartbeat: controla la frecuencia de ping/pong para mantener la conexión viva
  // Puedes cambiar estos valores según tus necesidades
  pingInterval: 25000, // cada 25 segundos el servidor envía un ping
  pingTimeout: 5000    // espera 5 segundos la respuesta pong antes de cerrar la conexión
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  console.log('Token recibido:', token ? 'Presente' : 'Ausente');
  
  if (!token) {
    console.log('No se proporcionó token');
    return next(new Error('Authentication error'));
  }
  
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error) {
      console.log('Error validando token:', error.message);
      return next(new Error('Invalid token'));
    }
    
    if (!user) {
      console.log('Usuario no encontrado');
      return next(new Error('User not found'));
    }
    
    socket.user = user;
    console.log('Usuario autenticado:', user.email);
    next();
  } catch (err) {
    console.error('Error en middleware de autenticación:', err);
    next(new Error('Authentication failed'));
  }
});

require('./socketHandler')(io, supabase);

httpServer.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});