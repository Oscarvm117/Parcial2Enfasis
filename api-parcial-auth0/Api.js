const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(cors());


const KEYCLOAK_URL = 'http://localhost:8080';
const REALM = 'parcial-oauth';
const JWKS_URI = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`;

// Cliente para verificar tokens JWT
const client = jwksClient({
  jwksUri: JWKS_URI,
  cache: true,
  rateLimit: true
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Token no proporcionado',
      mensaje: 'Debe incluir: Authorization: Bearer <token>' 
    });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, getKey, {
    algorithms: ['RS256'],
    issuer: `${KEYCLOAK_URL}/realms/${REALM}`
  }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ 
        error: 'Token inválido o expirado',
        detalle: err.message 
      });
    }
    
    req.user = decoded;
    next();
  });
}

// Verificar roles de Keycloak
function requiereRol(...rolesRequeridos) {
  return (req, res, next) => {
    const resourceAccess = req.user.resource_access || {};
    
    // Verificar en microservicio-cliente o frontend-app
    const microRoles = resourceAccess['microserviciocliente']?.roles || [];
    const frontendRoles = resourceAccess['frontendapp']?.roles || [];
    const todosLosRoles = [...microRoles, ...frontendRoles];
    
    const tienePermiso = rolesRequeridos.some(rol => todosLosRoles.includes(rol));
    
    if (!tienePermiso) {
      return res.status(403).json({ 
        error: 'Permisos insuficientes',
        rolesRequeridos: rolesRequeridos,
        rolesActuales: todosLosRoles
      });
    }
    
    next();
  };
}

// ========================================
// ENDPOINTS
// ========================================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    mensaje: 'API funcionando con Keycloak',
    timestamp: new Date().toISOString()
  });
});

// MICROSERVICIO
app.get('/api/servicios/productos', verificarToken, requiereRol('service-read'), (req, res) => {
  res.json({
    mensaje: 'Acceso permitido con Client Credentials',
    cliente: req.user.azp,
    roles: req.user.resource_access,
    datos: [
      { id: 1, nombre: 'Laptop', precio: 1200 },
      { id: 2, nombre: 'Mouse', precio: 25 }
    ]
  });
});

app.post('/api/servicios/productos', verificarToken, requiereRol('service-write'), (req, res) => {
  res.json({
    mensaje: 'Producto creado exitosamente',
    cliente: req.user.azp,
    producto: req.body
  });
});

// USUARIOS
app.get('/api/usuarios/perfil', verificarToken, requiereRol('user-read'), (req, res) => {
  res.json({
    mensaje: 'Acceso permitido con token de usuario',
    usuario: req.user.preferred_username,
    email: req.user.email,
    perfil: {
      nombre: 'Oscar Vergara',
      edad: 21
    }
  });
});

app.put('/api/usuarios/perfil', verificarToken, requiereRol('user-write'), (req, res) => {
  res.json({
    mensaje: 'Perfil actualizado',
    usuario: req.user.preferred_username,
    datos: req.body
  });
});

app.get('/api/token-info', verificarToken, (req, res) => {
  res.json({
    mensaje: 'Info del token',
    datos: {
      cliente: req.user.azp,
      usuario: req.user.preferred_username || 'N/A',
      roles: req.user.resource_access,
      expira: new Date(req.user.exp * 1000).toISOString()
    }
  });
});

// HTTPS
const httpsOptions = {
  key: fs.existsSync('./server.key') ? fs.readFileSync('./server.key') : null,
  cert: fs.existsSync('./server.cert') ? fs.readFileSync('./server.cert') : null
};

if (httpsOptions.key && httpsOptions.cert) {
  https.createServer(httpsOptions, app).listen(3000, () => {
    console.log('API corriendo en https://localhost:3000');
    console.log('Usando Keycloak en ' + KEYCLOAK_URL);
  });
} else {
  app.listen(3000, () => {
    console.log('API en http://localhost:3000');
    console.log(' Genera certificados HTTPS');
  });
}

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Error interno', detalle: err.message });
});