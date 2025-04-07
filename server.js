require('dotenv').config();
const express = require('express');
const multer = require('multer');
const ftp = require('basic-ftp');
const mysql = require('mysql2/promise'); // Usamos la versión promise para mejor manejo
const cors = require('cors');
const stream = require('stream');
const xss = require('xss');
const helmet = require('helmet');

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: ['https://cartelera-jw8a.onrender.com', 'http://localhost:4200'],
  credentials: true
}));
app.use(helmet());

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

// Middleware para sanitizar inputs contra XSS
const sanitizeInputs = (req, res, next) => {
  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key].trim());
      }
    }
  }
  next();
};

// Multer: almacenamiento en memoria
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Configuración FTP
const FTP_CONFIG = {
  host: process.env.FTP_HOST,
  user: process.env.FTP_USER,
  password: process.env.FTP_PASSWORD,
  secure: false
};

const FTP_BASE_PATH = process.env.FTP_BASE_PATH;
const PUBLIC_URL = process.env.PUBLIC_URL;

// --- Middleware de autenticación ---
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Acceso no autorizado');

  try {
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const [userId, userName] = decoded.split(':');
    
    // Consulta parametrizada contra SQL injection
    const [results] = await db.execute(
      'SELECT id FROM login WHERE id = ? AND strNombre = ?', 
      [userId, userName]
    );
    
    if (results.length === 0) return res.status(401).send('Token inválido');
    req.user = { id: userId, nombre: userName };
    next();
  } catch (err) {
    res.status(401).send('Token inválido');
  }
}

// --- Rutas FTP (protegidas) ---
app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded.');

  try {
    const client = new ftp.Client();
    await client.access(FTP_CONFIG);
    await client.ensureDir(FTP_BASE_PATH);

    const filePath = `${FTP_BASE_PATH}/${xss(req.file.originalname)}`;
    const bufferStream = stream.Readable.from(req.file.buffer);
    await client.uploadFrom(bufferStream, filePath);
    client.close();

    res.send({
      message: 'Archivo subido con éxito',
      url: `${PUBLIC_URL}/${xss(req.file.originalname)}`
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al subir el archivo al FTP.');
  }
});

// --- Rutas de Películas con protección SQL y XSS ---
app.get('/movies', async (req, res) => {
  try {
    // Consulta segura con parámetros
    const [results] = await db.query('SELECT * FROM cine');
    res.send(results);
  } catch (err) {
    res.status(500).send('Error en consulta a la base de datos.');
  }
});

app.post('/movies', authMiddleware, sanitizeInputs, async (req, res) => {
  const { strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen, strTrailerURL } = req.body;
  
  if (!strNombre || !strGenero || !strSinapsis || !strHorario || !idSala || !strImagen) {
    return res.status(400).json({ error: 'Faltan parámetros obligatorios' });
  }

  try {
    // Consulta parametrizada
    const [result] = await db.execute(
      `INSERT INTO cine 
      (strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen, strTrailerURL) 
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen, strTrailerURL || null]
    );
    
    res.status(201).send({ 
      message: 'Película agregada correctamente', 
      id: result.insertId 
    });
  } catch (err) {
    res.status(500).send('Error al agregar película.');
  }
});

app.put('/movies/:id', authMiddleware, sanitizeInputs, async (req, res) => {
  const { id } = req.params;
  const { strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen, strTrailerURL } = req.body;
  
  if (!strNombre || !strGenero || !strSinapsis || !strHorario || !idSala || !strImagen) {
    return res.status(400).json({ error: 'Faltan parámetros obligatorios' });
  }

  try {
    // Consulta parametrizada
    await db.execute(
      `UPDATE cine SET 
      strNombre = ?, 
      strGenero = ?, 
      strSinapsis = ?, 
      strHorario = ?, 
      idSala = ?, 
      strImagen = ?,
      strTrailerURL = ?
      WHERE id = ?`,
      [strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen, strTrailerURL || null, id]
    );
    
    res.send({ message: 'Película actualizada correctamente' });
  } catch (err) {
    res.status(500).send('Error al actualizar película.');
  }
});

app.delete('/movies/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    // Consulta parametrizada
    await db.execute('DELETE FROM cine WHERE id = ?', [id]);
    res.send({ message: 'Película eliminada correctamente' });
  } catch (err) {
    res.status(500).send('Error al eliminar película.');
  }
});

// --- Login con protección contra SQL injection ---
app.post('/login', sanitizeInputs, async (req, res) => {
  const { strNombre, strPwd } = req.body;
  if (!strNombre || !strPwd) {
    return res.status(400).json({ error: 'Faltan credenciales' });
  }

  try {
    // Consulta parametrizada segura
    const [results] = await db.execute(
      'SELECT id, strNombre, idEstadoUsuario, rol FROM login WHERE strNombre = ? AND strPwd = ? AND idEstadoUsuario = 1',
      [strNombre, strPwd]
    );
    
    if (results.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas o usuario inactivo' });
    }

    const usuario = results[0];
    const fakeToken = Buffer.from(`${usuario.id}:${usuario.strNombre}`).toString('base64');

    res.json({
      id: usuario.id,
      nombre: usuario.strNombre,
      rol: usuario.rol,
      token: fakeToken
    });
  } catch (err) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// --- Ruta de prueba ---
app.get('/', (req, res) => {
  res.send('Backend funcionando. Usa /login para autenticarte.');
});

// Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});