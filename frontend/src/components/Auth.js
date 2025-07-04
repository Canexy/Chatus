import React, { useState, useEffect } from 'react';
import { supabase } from '../supabase';

export default function Auth() {
  const [identifier, setIdentifier] = useState(''); // Solo email
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [isLogin, setIsLogin] = useState(true);
  const [error, setError] = useState('');
  const [username, setUsername] = useState('');
  const [usernameAvailable, setUsernameAvailable] = useState(true);
  const [showReset, setShowReset] = useState(false);
  const [resetSent, setResetSent] = useState(false);

  // Verificar disponibilidad de nombre de usuario
  const checkUsernameAvailability = async (username) => {
    if (!username.trim()) return true;
    
    const { data, error } = await supabase
      .from('profiles')
      .select('username')
      .eq('username', username)
      .maybeSingle();
    
    if (error) {
      console.error('Error verificando usuario:', error);
      return true; // Permitir continuar por si acaso
    }
    
    return !data; // Disponible si no se encontró
  };

  const handleUsernameChange = async (e) => {
    const value = e.target.value;
    setUsername(value);
    
    if (value.trim() && !isLogin) {
      const available = await checkUsernameAvailability(value);
      setUsernameAvailable(available);
    }
  };

  // Modificado: login por usuario o email
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      if (isLogin) {
        if (!identifier.includes('@')) {
          throw new Error('Debes iniciar sesión con tu correo electrónico.');
        }
        const { data, error } = await supabase.auth.signInWithPassword({
          email: identifier,
          password
        });
        if (error) throw error;
      } else {
        // Validar nombre de usuario antes de registrar
        if (username) {
          const available = await checkUsernameAvailability(username);
          if (!available) {
            throw new Error('El nombre de usuario ya está en uso');
          }
        }
        const { data, error: signUpError } = await supabase.auth.signUp({
          email: identifier,
          password,
          options: {
            emailRedirectTo: window.location.origin,
            data: {
              username: username || identifier.split('@')[0]
            }
          }
        });
        if (signUpError) throw signUpError;
        alert('¡Registro exitoso! Por favor verifica tu email.');
      }
    } catch (err) {
      setError(err.message);
      console.error('Error de autenticación:', err);
    } finally {
      setLoading(false);
    }
  };

  // Modificado: recuperación de contraseña por usuario o email
  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');
    setResetSent(false);
    setLoading(true);
    try {
      if (!identifier.includes('@')) {
        throw new Error('Debes ingresar tu correo electrónico para recuperar la contraseña.');
      }
      const { error } = await supabase.auth.resetPasswordForEmail(identifier, {
        redirectTo: window.location.origin
      });
      if (error) throw error;
      setResetSent(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-xl">
      <h1 className="text-2xl font-bold mb-6 text-center text-blue-600">
        {isLogin ? 'Iniciar sesión' : 'Registrarse'} en ChatUs
      </h1>
      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">{error}</div>
      )}
      {resetSent && (
        <div className="mb-4 p-3 bg-green-100 text-green-700 rounded">
          Se ha enviado un correo para restablecer la contraseña.
        </div>
      )}
      {showReset ? (
        <form onSubmit={handleResetPassword}>
          <div className="mb-4">
            <label htmlFor="identifier" className="block text-gray-700 mb-2">Correo electrónico</label>
            <input
              id="identifier"
              type="email"
              placeholder="Correo electrónico"
              value={identifier}
              onChange={e => setIdentifier(e.target.value)}
              className="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <button
            disabled={loading}
            className={`w-full py-3 px-4 rounded text-white font-medium ${loading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
          >
            {loading ? 'Cargando...' : 'Enviar enlace de recuperación'}
          </button>
          <div className="mt-4 text-center">
            <button type="button" onClick={() => setShowReset(false)} className="text-blue-600 hover:text-blue-800 underline">
              Volver al login
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={handleSubmit}>
          {!isLogin && (
            <div className="mb-4">
              <label htmlFor="username" className="block text-gray-700 mb-2">
                Nombre de usuario
                {username && !usernameAvailable && (
                  <span className="ml-2 text-red-500 text-sm">(Ya en uso)</span>
                )}
              </label>
              <input
                id="username"
                type="text"
                placeholder="Tu nombre único"
                value={username}
                onChange={handleUsernameChange}
                className={`w-full px-4 py-2 border rounded focus:outline-none ${username && !usernameAvailable ? 'border-red-500 focus:ring-red-500' : 'focus:ring-blue-500'}`}
                required
              />
              <p className="text-sm text-gray-500 mt-1">
                Este será tu nombre visible en el chat
              </p>
            </div>
          )}
          <div className="mb-4">
            <label htmlFor="identifier" className="block text-gray-700 mb-2">
              Email
            </label>
            <input
              id="identifier"
              type="email"
              placeholder="Email"
              value={identifier}
              onChange={e => setIdentifier(e.target.value)}
              className="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
          <div className="mb-6">
            <label htmlFor="password" className="block text-gray-700 mb-2">Contraseña</label>
            <input
              id="password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
              minLength={6}
            />
          </div>
          <button
            disabled={loading || (!isLogin && username && !usernameAvailable)}
            className={`w-full py-3 px-4 rounded text-white font-medium ${loading || (!isLogin && username && !usernameAvailable) ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
          >
            {loading ? 'Cargando...' : isLogin ? 'Iniciar sesión' : 'Registrarme'}
          </button>
        </form>
      )}
      <div className="mt-6 text-center">
        <button
          onClick={() => setIsLogin(!isLogin)}
          className="text-blue-600 hover:text-blue-800 underline"
        >
          {isLogin ? '¿No tienes cuenta? Regístrate aquí' : '¿Ya tienes cuenta? Inicia sesión aquí'}
        </button>
        <button
          onClick={() => setShowReset(true)}
          className="ml-4 text-blue-600 hover:text-blue-800 underline"
        >
          ¿Olvidaste tu contraseña?
        </button>
      </div>
      {isLogin && (
        <div className="mt-4 text-yellow-700 bg-yellow-100 p-2 rounded text-sm">
          Sólo puedes iniciar sesión con tu correo electrónico. Si cambias tu nombre de usuario, tu acceso seguirá siendo por email.
        </div>
      )}
      {!isLogin && (
        <div className="mt-4 text-yellow-700 bg-yellow-100 p-2 rounded text-sm">
          Podrás cambiar tu nombre de usuario más adelante desde tu perfil.
        </div>
      )}
    </div>
  );
}