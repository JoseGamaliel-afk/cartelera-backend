require('dotenv').config();
const express = require('express');
const multer = require('multer');
const ftp = require('basic-ftp');
const mysql = require('mysql2');
const cors = require('cors');
const stream = require('stream');
const xss = require('xss');
const helmet = require('helmet');

const app = express();

// Configuración mejorada de CORS
app.use(cors({
  origin: ['https://cartelera-jw8a.onrender.com', 'http://localhost:4200'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(helmet());
app.use(express.json());

// Configuración de MySQL
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Verificar conexión a la base de datos
db.getConnection((err, connection) => {
  if (err) {
    console.error('Error de conexión a la base de datos:', err);
  } else {
    console.log('✅ Conexión exitosa a la base de datos');
    connection.release();
  }
});

// Configuración FTP
const FTP_CONFIG = {
  host: process.env.FTP_HOST,
  user: process.env.FTP_USER,
  password: process.env.FTP_PASSWORD,
  secure: false
};

const FTP_BASE_PATH = process.env.FTP_BASE_PATH || '/uploads';
const PUBLIC_URL = process.env.PUBLIC_URL || 'https://cartelera-jw8a.onrender.com/uploads';

// --- Middleware para rutas API ---
const apiRouter = express.Router();
app.use('/api', apiRouter);

// --- Rutas FTP ---
const upload = multer({ storage: multer.memoryStorage() });

apiRouter.post('/ftp/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const client = new ftp.Client();
    await client.access(FTP_CONFIG);
    await client.ensureDir(FTP_BASE_PATH);

    const filePath = `${FTP_BASE_PATH}/${Date.now()}_${req.file.originalname}`;
    const bufferStream = stream.Readable.from(req.file.buffer);
    await client.uploadFrom(bufferStream, filePath);
    client.close();

    res.json({
      message: 'Archivo subido con éxito',
      url: `${PUBLIC_URL}/${filePath.split('/').pop()}`
    });
  } catch (err) {
    console.error('FTP Error:', err);
    res.status(500).json({ error: 'Error al subir el archivo' });
  }
});

// --- Rutas de Autenticación ---
const authRouter = express.Router();
apiRouter.use('/auth', authRouter);

authRouter.post('/login', (req, res) => {
  const { strNombre, strPwd } = req.body;
  
  if (!strNombre || !strPwd) {
    return res.status(400).json({ 
      error: 'Credenciales requeridas',
      code: 'CREDENTIALS_MISSING'
    });
  }

  const query = `SELECT id, strNombre, idEstadoUsuario, rol 
                FROM login 
                WHERE strNombre = ? AND strPwd = ? AND idEstadoUsuario = 1`;
  
  db.query(query, [xss(strNombre), xss(strPwd)], (err, results) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: 'Error del servidor', code: 'DB_ERROR' });
    }
    
    if (results.length === 0) {
      return res.status(401).json({ 
        error: 'Credenciales inválidas o usuario inactivo',
        code: 'INVALID_CREDENTIALS' 
      });
    }

    const usuario = results[0];
    res.json({
      id: usuario.id,
      nombre: usuario.strNombre,
      rol: usuario.rol
    });
  });
});

// --- Rutas de Películas ---
const moviesRouter = express.Router();
apiRouter.use('/movies', moviesRouter);

moviesRouter.get('/', (req, res) => {
  db.query('SELECT * FROM cine', (err, results) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: 'Error en la consulta' });
    }
    res.json(results);
  });
});

// ... (mantén tus otras rutas de películas igual pero con moviesRouter)

// --- Manejo de Errores ---
app.use((err, req, res, next) => {
  console.error('Global Error:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// --- Inicio del Servidor ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📌 Rutas disponibles:`);
  console.log(`- POST   /api/auth/login`);
  console.log(`- GET    /api/movies`);
  console.log(`- POST   /api/ftp/upload`);
});