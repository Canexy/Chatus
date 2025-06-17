module.exports = (io, supabase) => {
  io.on('connection', (socket) => {
    console.log(`Usuario conectado: ${socket.user?.email || 'Desconocido'}`);
    console.log(`Total de clientes conectados: ${io.engine.clientsCount}`);
    
    // Manejar nuevos mensajes
    socket.on('new_message', async (message) => {
      console.log('Nuevo mensaje recibido de', socket.user?.email, ':', message);
      
      try {
        if (!socket.user) {
          console.error('Usuario no autenticado en socket');
          return;
        }
        
        // Guardar en la base de datos
        const { data, error } = await supabase
          .from('messages')
          .insert({
            user_id: socket.user.id,
            content: message.text,
            file_url: message.file_url
          })
          .select('*');  // Solicitar datos de retorno
        
        if (error) {
          console.error('Error al guardar mensaje:', error);
          return;
        }
        
        // Verificar si se insertó correctamente
        if (!data || data.length === 0) {
          console.error('No se recibieron datos al insertar el mensaje');
          return;
        }
        
        console.log('Mensaje guardado en DB:', data[0].id);
        
        // Obtener nombre de usuario (con manejo de errores)
        let username = socket.user.email;
        try {
          const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('username')
            .eq('user_id', socket.user.id)
            .maybeSingle();  // Usar maybeSingle para evitar error cuando no hay resultados
            
          if (!profileError && profile) {
            username = profile.username;
          }
        } catch (profileErr) {
          console.error('Error obteniendo perfil:', profileErr);
        }
        
        // Construir objeto de mensaje para enviar
        const messageToSend = {
          ...data[0],
          profiles: {
            username
          }
        };
        
        console.log(`Enviando mensaje a ${io.engine.clientsCount} clientes conectados...`);
        
        // Enviar a todos los clientes EXCEPTO al que envió el mensaje
        socket.broadcast.emit('message_received', messageToSend);
        
        // Enviar solo al cliente que originó el mensaje (para mantener consistencia)
        socket.emit('message_received', messageToSend);
        
      } catch (err) {
        console.error('Error en el manejo del mensaje:', err);
      }
    });
    
    // Evento admin: limpiar todos los mensajes y resetear id (sin emitir chat_cleared)
    socket.on('admin_clear_all_messages', async () => {
      try {
        // Verificar si el usuario es admin
        const { data: profile, error } = await supabase
          .from('profiles')
          .select('is_admin')
          .eq('user_id', socket.user.id)
          .maybeSingle();
        if (error || !profile?.is_admin) {
          console.log('Intento de limpieza global por usuario no admin:', socket.user?.email);
          return;
        }
        // Borrar todos los mensajes
        await supabase.from('messages').delete().neq('id', 0);
        // Resetear la secuencia de IDs (opcional, si tienes la función RPC)
        if (supabase.rpc) {
          await supabase.rpc('reset_messages_id_seq');
        }
        console.log('Todos los mensajes han sido eliminados por el admin.');
        
      } catch (err) {
        console.error('Error en limpieza global de mensajes:', err);
      }
    });
    
    // Manejar desconexión
    socket.on('disconnect', (reason) => {
      console.log(`Usuario desconectado (${socket.user?.email || 'Desconocido'}): ${reason}`);
      console.log(`Clientes restantes: ${io.engine.clientsCount}`);
    });
    
    // Manejar error de socket
    socket.on('error', (error) => {
      console.error(`Error en socket de ${socket.user?.email || 'Desconocido'}:`, error);
    });
    
    // Cerrar conexiones inactivas después de 1 minuto
    const inactivityTimer = setTimeout(() => {
      if (socket.connected) {
        console.log(`Cerrando conexión inactiva de ${socket.user?.email || 'Desconocido'}`);
        socket.disconnect();
      }
    }, 60000); // 1 minuto
    
    // Limpiar timer al desconectar
    socket.on('disconnect', () => {
      clearTimeout(inactivityTimer);
    });
  });
};