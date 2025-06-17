import React, { useState, useEffect, useRef } from 'react';
import { supabase } from '../supabase';
import io from 'socket.io-client';

const Chat = ({ session, onProfileClick }) => {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [showAdminMenu, setShowAdminMenu] = useState(false);
  const socketRef = useRef(null);
  const messagesEndRef = useRef(null);
  const isInitialMount = useRef(true);
  const reconnectTimeout = useRef(null);

  // Detectar si el usuario es admin
  useEffect(() => {
    const fetchProfile = async () => {
      const { data, error } = await supabase
        .from('profiles')
        .select('is_admin')
        .eq('user_id', session.user.id)
        .maybeSingle();
      if (!error && data && data.is_admin) {
        setIsAdmin(true);
      } else {
        setIsAdmin(false);
      }
    };
    if (session?.user?.id) fetchProfile();
  }, [session]);

  // 1. Conectar a Socket.IO con autenticación
  useEffect(() => {
    if (!session) return;

    if (isInitialMount.current) {
      const socket = io(process.env.REACT_APP_BACKEND_URL, {
        transports: ['websocket'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 30, // más intentos
        reconnectionDelay: 2000,  // 2 segundos entre intentos
        reconnectionDelayMax: 10000, // hasta 10 segundos entre intentos
        withCredentials: true,
        auth: {
          token: session.access_token
        }
      });

      socketRef.current = socket;

      const handleConnect = () => {
        setIsConnected(true);
        setIsReconnecting(false);
        if (reconnectTimeout.current) {
          clearTimeout(reconnectTimeout.current);
          reconnectTimeout.current = null;
        }
      };

      const handleDisconnect = (reason) => {
        setIsConnected(false);
        setIsReconnecting(true);
        // Si tras 10s no reconecta, mostrar desconexión real
        reconnectTimeout.current = setTimeout(() => {
          setIsReconnecting(false);
        }, 10000);
      };

      const handleReconnectAttempt = () => {
        setIsReconnecting(true);
      };

      const handleReconnect = () => {
        setIsConnected(true);
        setIsReconnecting(false);
        if (reconnectTimeout.current) {
          clearTimeout(reconnectTimeout.current);
          reconnectTimeout.current = null;
        }
      };

      const handleConnectError = (err) => {
        setIsConnected(false);
        setIsReconnecting(false);
        console.error('Error de conexión:', err.message);
      };

      const handleError = (err) => {
        console.error('Error general de Socket.IO:', err);
      };

      const handleMessageReceived = (message) => {
        setMessages(prevMessages => [...prevMessages, message]);
      };

      socket.on('connect', handleConnect);
      socket.on('disconnect', handleDisconnect);
      socket.on('reconnect_attempt', handleReconnectAttempt);
      socket.on('reconnect', handleReconnect);
      socket.on('connect_error', handleConnectError);
      socket.on('error', handleError);
      socket.on('message_received', handleMessageReceived);

      isInitialMount.current = false;
    }

    return () => {
      if (!isInitialMount.current && socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
        isInitialMount.current = true;
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
        reconnectTimeout.current = null;
      }
    };
  }, [session]);

  // 2. (Eliminada la lógica de desconexión al cambiar de pestaña)

  // 3. Cargar mensajes históricos al inicio
  useEffect(() => {
    const fetchMessages = async () => {
      const { data, error } = await supabase
        .from('messages')
        .select(`
          id,
          content,
          file_url,
          created_at,
          profiles:user_id (username)
        `)
        .order('created_at', { ascending: true })
        .limit(50);
      if (!error && data) setMessages(data);
    };
    fetchMessages();
  }, []);

  // 4. Enviar mensaje
  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!newMessage.trim()) return;
    try {
      if (!isConnected || !socketRef.current) {
        return;
      }
      socketRef.current.emit('new_message', {
        text: newMessage,
        user_id: session.user.id
      });
      setNewMessage('');
    } catch (error) {
      console.error('Error sending message:', error);
    }
  };

  // 5. Scroll automático al último mensaje
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // 6. Mensaje de estado
  let statusText = '';
  if (isConnected) statusText = '🟢 Conectado';
  else if (isReconnecting) statusText = '🟡 Reconectando...';
  else statusText = '🔴 Desconectado';

  // Añadir función para limpiar el historial local
  const handleClearChat = () => {
    setMessages([]);
  };

  // Función admin: limpiar todos los mensajes de la base de datos y resetear el id usando la función RPC segura
  const handleAdminDeleteAllMessages = async () => {
    if (!window.confirm('¿Seguro que quieres borrar TODOS los mensajes del chat y resetear el contador de IDs? Esta acción es irreversible.')) return;
    const { error } = await supabase.rpc('admin_clear_all_messages');
    if (!error) {
      setMessages([]);
      alert('Todos los mensajes han sido eliminados y el contador de IDs ha sido reseteado.');
      setShowAdminMenu(false);
    } else {
      alert('Error al borrar mensajes o resetear IDs: ' + error.message);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-gray-100">
      {/* Barra superior con botones */}
      <div className="bg-blue-600 text-white p-4 shadow-md flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold">ChatUs</h1>
          <p className="text-sm">
            {statusText} | Bienvenido, {session.user.email}
          </p>
        </div>
        <div className="flex space-x-2 items-center">
          {isAdmin && (
            <div className="relative">
              <button
                onClick={() => setShowAdminMenu((v) => !v)}
                className="bg-purple-700 hover:bg-purple-800 px-3 py-1 rounded text-sm mr-2"
              >
                Admin
              </button>
              {showAdminMenu && (
                <div className="absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-700 rounded shadow-lg z-50">
                  <button
                    onClick={handleAdminDeleteAllMessages}
                    className="block w-full text-left px-4 py-2 text-red-400 hover:bg-gray-700 hover:text-red-600"
                  >
                    Limpiar todos los mensajes
                  </button>
                </div>
              )}
            </div>
          )}
          <button 
            onClick={onProfileClick}
            className="bg-yellow-500 hover:bg-yellow-600 px-3 py-1 rounded text-sm"
          >
            Perfil
          </button>
          <button 
            onClick={handleClearChat}
            className="bg-gray-500 hover:bg-gray-600 px-3 py-1 rounded text-sm"
          >
            Limpiar chat
          </button>
          <button 
            onClick={() => supabase.auth.signOut()}
            className="bg-red-500 hover:bg-red-600 px-3 py-1 rounded text-sm"
          >
            Cerrar sesión
          </button>
        </div>
      </div>

      {/* Área de mensajes */}
      <div className="flex-1 overflow-y-auto p-4 bg-white">
        {messages.length === 0 ? (
          <div className="text-center text-gray-500 py-8">
            <p>No hay mensajes aún. ¡Sé el primero en enviar uno!</p>
          </div>
        ) : (
          messages.map((message) => (
            <div key={message.id} className="mb-4">
              <div className="flex items-start">
                <div className="bg-gray-200 border-2 border-dashed rounded-xl w-8 h-8 mr-2" />
                <div>
                  <strong className="text-blue-600">
                    {message.profiles?.username || 'Anónimo'}
                  </strong>
                  <p className="text-gray-800">{message.content}</p>
                  {message.file_url && (
                    <div className="mt-2">
                      <img 
                        src={message.file_url} 
                        alt="Adjunto" 
                        className="max-w-xs rounded"
                      />
                    </div>
                  )}
                  <span className="text-xs text-gray-500">
                    {new Date(message.created_at).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Formulario de envío */}
      <form onSubmit={handleSendMessage} className="p-4 bg-white border-t">
        <div className="flex">
          <input
            type="text"
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            className="flex-1 p-2 border rounded-l focus:outline-none"
            placeholder="Escribe un mensaje..."
          />
          <button
            type="submit"
            className="bg-blue-600 text-white px-4 py-2 rounded-r hover:bg-blue-700 disabled:bg-blue-400"
            disabled={!isConnected && !isReconnecting}
          >
            Enviar
          </button>
        </div>
        {!isConnected && !isReconnecting && (
          <p className="text-red-500 text-sm mt-2">
            No estás conectado. Intenta recargar la página.
          </p>
        )}
      </form>
    </div>
  );
};

export default Chat;