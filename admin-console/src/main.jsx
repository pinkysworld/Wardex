import React from 'react';
import ReactDOM from 'react-dom/client';
import { AuthProvider, ThemeProvider, ToastProvider } from './hooks.jsx';
import App from './App.jsx';
import './App.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  </React.StrictMode>
);
