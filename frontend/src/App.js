import { supabase } from './supabase';
import React, { useState, useEffect } from 'react';
import Auth from './components/Auth';
import Chat from './components/Chat';
import Profile from './components/Profile';

function App() {
  const [session, setSession] = useState(null);
  const [showProfile, setShowProfile] = useState(false);
  const [isCheckingSession, setIsCheckingSession] = useState(true);

  useEffect(() => {
    // Verificar sesión existente
    const checkSession = async () => {
      const { data: { session }, error } = await supabase.auth.getSession();
      if (error) {
        console.error("Error obteniendo sesión:", error);
      } else {
        setSession(session);
      }
      setIsCheckingSession(false);
    };

    // Escuchar cambios de autenticación
    const { data: authListener } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        setSession(session);
      }
    );

    // Inicializar app
    checkSession();

    // Limpiar listeners al desmontar
    return () => {
      authListener?.subscription.unsubscribe();
    };
  }, []);

  // Renderizar contenido basado en el estado
  if (isCheckingSession) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p>Cargando...</p>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-4">
      {showProfile ? (
        <Profile 
          session={session} 
          onBack={() => setShowProfile(false)} 
        />
      ) : !session ? (
        <Auth />
      ) : (
        <Chat 
          session={session} 
          onProfileClick={() => setShowProfile(true)} 
        />
      )}
    </div>
  );
}

export default App;