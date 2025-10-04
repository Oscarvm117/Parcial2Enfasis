// ========================================
// API PROTEGIDO CON AUTH0
// ========================================

// 1. CREAR PROYECTO:
// mkdir api-parcial-auth0
// cd api-parcial-auth0
// npm init -y

// 2. INSTALAR DEPENDENCIAS:
// npm install express express-oauth2-jwt-bearer cors https fs

const express = require('express');
const { auth, requiredScopes } = require('express-oauth2-jwt-bearer');
const cors = require('cors');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(cors());

// ========================================
// CONFIGURACIÓN AUTH0
// ⚠️ REEMPLAZA CON TUS DATOS
// ========================================
const AUTH0_DOMAIN = 'dev-uilvef2fvivglwd5.us.auth0.com'; // ← CAMBIA ESTO
const AUTH0_AUDIENCE = 'https://api-parcial.com'; // ← Tu API Identifier

// ========================================
// MIDDLEWARE: Verificar Access Token
// ========================================
const checkJwt = auth({
  audience: AUTH0_AUDIENCE,
  issuerBaseURL: `https://${AUTH0_DOMAIN}/`,
  tokenSigningAlg: 'RS256'
});

// ========================================
// ENDPOINTS PÚBLICOS
// ========================================

// Health check (sin protección)
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    mensaje: 'API funcionando correctamente con Auth0',
    timestamp: new Date().toISOString(),
    auth0_domain: AUTH0_DOMAIN
  });
});

// ========================================
// ENDPOINTS PROTEGIDOS - SERVICIOS
// (Client Credentials - Microservicio)
// ========================================

// GET - Requiere scope: service:read
app.get('/api/servicios/productos', 
  checkJwt, 
  requiredScopes('service:read'),
  (req, res) => {
    res.json({
      mensaje: 'Acceso permitido con Client Credentials (service:read)',
      cliente: req.auth.payload.azp || req.auth.payload.client_id,
      scopes: req.auth.payload.scope,
      tipo_flujo: 'Client Credentials',
      datos: [
        { id: 1, nombre: 'Laptop Dell XPS', precio: 1200, stock: 15 },
        { id: 2, nombre: 'Mouse Logitech MX', precio: 85, stock: 50 },
        { id: 3, nombre: 'Teclado Mecánico', precio: 150, stock: 30 },
        { id: 4, nombre: 'Monitor 4K', precio: 450, stock: 8 }
      ]
    });
  }
);

// POST - Requiere scope: service:write
app.post('/api/servicios/productos',
  checkJwt,
  requiredScopes('service:write'),
  (req, res) => {
    const nuevoProducto = req.body;
    
    res.json({
      mensaje: 'Producto creado exitosamente (service:write)',
      cliente: req.auth.payload.azp || req.auth.payload.client_id,
      scopes: req.auth.payload.scope,
      tipo_flujo: 'Client Credentials',
      producto_creado: {
        id: Math.floor(Math.random() * 1000),
        ...nuevoProducto,
        fecha_creacion: new Date().toISOString()
      }
    });
  }
);

// PUT - Requiere scope: service:write
app.put('/api/servicios/productos/:id',
  checkJwt,
  requiredScopes('service:write'),
  (req, res) => {
    const { id } = req.params;
    const datosActualizados = req.body;
    
    res.json({
      mensaje: `Producto ${id} actualizado exitosamente`,
      cliente: req.auth.payload.azp,
      producto_actualizado: {
        id: parseInt(id),
        ...datosActualizados,
        fecha_actualizacion: new Date().toISOString()
      }
    });
  }
);

// ========================================
// ENDPOINTS PROTEGIDOS - USUARIOS
// (Password Grant + Refresh Token)
// ========================================

// GET - Requiere scope: user:read
app.get('/api/usuarios/perfil',
  checkJwt,
  requiredScopes('user:read'),
  (req, res) => {
    // Auth0 incluye el sub (subject) que identifica al usuario
    const userId = req.auth.payload.sub;
    const email = req.auth.payload.email || 'N/A';
    
    res.json({
      mensaje: 'Acceso permitido con token de usuario (user:read)',
      usuario_id: userId,
      email: email,
      scopes: req.auth.payload.scope,
      tipo_flujo: 'Password Grant (Usuario)',
      perfil: {
        nombre: 'oscar',
        edad: 22,
        pais: 'COL',
        ciudad: 'bogota',
        ocupacion: 'Desarrollador',
        miembro_desde: '2025-09-4'
      }
    });
  }
);

// PUT - Requiere scope: user:write
app.put('/api/usuarios/perfil',
  checkJwt,
  requiredScopes('user:write'),
  (req, res) => {
    const userId = req.auth.payload.sub;
    const datosActualizados = req.body;
    
    res.json({
      mensaje: 'Perfil actualizado exitosamente (user:write)',
      usuario_id: userId,
      email: req.auth.payload.email,
      scopes: req.auth.payload.scope,
      datos_actualizados: datosActualizados,
      fecha_actualizacion: new Date().toISOString()
    });
  }
);

// GET - Requiere scope: user:read (endpoint adicional)
app.get('/api/usuarios/historial',
  checkJwt,
  requiredScopes('user:read'),
  (req, res) => {
    res.json({
      mensaje: 'Historial de compras del usuario',
      usuario_id: req.auth.payload.sub,
      historial: [
        { id: 1, producto: 'Laptop', fecha: '2024-10-01', monto: 1200 },
        { id: 2, producto: 'Mouse', fecha: '2024-10-15', monto: 85 }
      ]
    });
  }
);

// ========================================
// ENDPOINT DE DEBUG (útil para verificar tokens)
// ========================================
app.get('/api/token-info',
  checkJwt,
  (req, res) => {
    const payload = req.auth.payload;
    
    res.json({
      mensaje: 'Información del token decodificado',
      token_valido: true,
      datos_token: {
        tipo: payload.gty || 'client-credentials',
        cliente: payload.azp || payload.client_id,
        usuario: payload.sub,
        email: payload.email || 'N/A (es un servicio)',
        scopes: payload.scope ? payload.scope.split(' ') : [],
        audiencia: payload.aud,
        emisor: payload.iss,
        emitido_en: new Date(payload.iat * 1000).toISOString(),
        expira_en: new Date(payload.exp * 1000).toISOString(),
        tiempo_restante_segundos: payload.exp - Math.floor(Date.now() / 1000)
      }
    });
  }
);

// ========================================
// MANEJO DE ERRORES
// ========================================

// Error cuando no hay token o es inválido
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Token no proporcionado o inválido',
      mensaje: err.message,
      detalles: 'Debe incluir header: Authorization: Bearer <tu_token>',
      codigo: err.code
    });
  }
  
  if (err.name === 'InsufficientScopeError') {
    return res.status(403).json({
      error: 'Permisos insuficientes',
      mensaje: 'El token no tiene los scopes necesarios',
      scopes_requeridos: err.expected,
      scopes_actuales: err.actual
    });
  }
  
  // Otros errores
  console.error('Error:', err);
  res.status(500).json({
    error: 'Error interno del servidor',
    mensaje: err.message
  });
});

// Ruta no encontrada
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint no encontrado',
    ruta_solicitada: req.path,
    metodo: req.method
  });
});

// ========================================
// INICIAR SERVIDOR HTTPS
// ========================================

const PORT = 3000;

// Opciones para HTTPS (certificados auto-firmados)
const httpsOptions = {
  key: fs.existsSync('./server.key') ? fs.readFileSync('./server.key') : null,
  cert: fs.existsSync('./server.cert') ? fs.readFileSync('./server.cert') : null
};

// Iniciar servidor
if (httpsOptions.key && httpsOptions.cert) {
  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║  🔒 API PROTEGIDO CORRIENDO EN HTTPS                  ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log(`║  URL: https://localhost:${PORT}                        ║`);
    console.log(`║  Auth0 Domain: ${AUTH0_DOMAIN.padEnd(30)} ║`);
    console.log('║  Estado: ✅ HTTPS Activo (certificado auto-firmado)  ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log('║  ENDPOINTS DISPONIBLES:                                ║');
    console.log('║  GET  /health                    (público)             ║');
    console.log('║  GET  /api/servicios/productos   (service:read)        ║');
    console.log('║  POST /api/servicios/productos   (service:write)       ║');
    console.log('║  GET  /api/usuarios/perfil       (user:read)           ║');
    console.log('║  PUT  /api/usuarios/perfil       (user:write)          ║');
    console.log('║  GET  /api/token-info            (cualquier token)     ║');
    console.log('╚════════════════════════════════════════════════════════╝');
  });
} else {
  // Fallback a HTTP si no hay certificados
  app.listen(PORT, () => {
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║  ⚠️  API CORRIENDO EN HTTP (NO SEGURO)                ║');
    console.log('╠════════════════════════════════════════════════════════╣');
    console.log(`║  URL: http://localhost:${PORT}                         ║`);
    console.log('║  ❌ ADVERTENCIA: Para el parcial NECESITAS HTTPS      ║');
    console.log('║                                                        ║');
    console.log('║  Genera certificados con:                              ║');
    console.log('║  openssl req -nodes -new -x509 \\                      ║');
    console.log('║    -keyout server.key -out server.cert -days 365      ║');
    console.log('╚════════════════════════════════════════════════════════╝');
  });
}

