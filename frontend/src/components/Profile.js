import React, { useState, useEffect } from 'react';
import { supabase } from '../supabase';

const Profile = ({ session, onBack }) => {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [usernameAvailable, setUsernameAvailable] = useState(true);

  // Cargar perfil actual
  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const { data, error } = await supabase
          .from('profiles')
          .select('username')
          .eq('user_id', session.user.id)
          .single();
        
        if (error) throw error;
        
        if (data) {
          setUsername(data.username);
        }
      } catch (err) {
        setError('Error cargando perfil: ' + err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchProfile();
  }, [session]);

  // Verificar disponibilidad de nombre de usuario
  const checkUsernameAvailability = async (username) => {
    if (!username.trim()) return true;
    
    const { data, error } = await supabase
      .from('profiles')
      .select('username')
      .eq('username', username)
      .neq('user_id', session.user.id) // Excluir el usuario actual
      .maybeSingle();
    
    if (error) {
      console.error('Error verificando usuario:', error);
      return true; // Permitir continuar
    }
    
    return !data; // Disponible si no se encontró
  };

  const handleUsernameChange = async (e) => {
    const value = e.target.value;
    setUsername(value);
    
    if (value.trim()) {
      const available = await checkUsernameAvailability(value);
      setUsernameAvailable(available);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    try {
      if (!username.trim()) {
        throw new Error('El nombre de usuario no puede estar vacío');
      }
      
      // Verificar disponibilidad
      const available = await checkUsernameAvailability(username);
      if (!available) {
        throw new Error('El nombre de usuario ya está en uso');
      }
      
      // Actualizar perfil
      const { error } = await supabase
        .from('profiles')
        .upsert({
          user_id: session.user.id,
          username: username
        });
      
      if (error) throw error;
      
      setSuccess('¡Nombre de usuario actualizado correctamente!');
      setTimeout(() => {
        onBack();
      }, 2000);
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) {
    return (
      <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-xl">
        <p>Cargando perfil...</p>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-xl">
      <h2 className="text-2xl font-bold mb-6 text-center text-blue-600">Editar perfil</h2>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}
      
      {success && (
        <div className="mb-4 p-3 bg-green-100 text-green-700 rounded">
          {success}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-gray-700 mb-2">
            Nombre de usuario
            {username && !usernameAvailable && (
              <span className="ml-2 text-red-500 text-sm">(Ya en uso)</span>
            )}
          </label>
          <input
            type="text"
            value={username}
            onChange={handleUsernameChange}
            className={`w-full px-4 py-2 border rounded focus:outline-none ${
              username && !usernameAvailable 
                ? 'border-red-500 focus:ring-red-500' 
                : 'focus:ring-blue-500'
            }`}
            required
          />
        </div>
        
        <div className="flex justify-between">
          <button
            type="button"
            onClick={onBack}
            className="px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600"
          >
            Volver al chat
          </button>
          <button
            type="submit"
            disabled={!usernameAvailable}
            className={`px-4 py-2 text-white rounded ${
              usernameAvailable 
                ? 'bg-blue-600 hover:bg-blue-700' 
                : 'bg-gray-400 cursor-not-allowed'
            }`}
          >
            Actualizar
          </button>
        </div>
      </form>
    </div>
  );
};

export default Profile;