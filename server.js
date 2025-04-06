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
app.use(express.json());
app.use(cors({
  origin: 'https://cartelera-jw8a.onrender.com/',
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

// Verificar conexión a la base de dato
db.getConnection((err, connection) => {
  if (err) {
    console.error('Error de conexión a la base de datos:', err);
  } else {
    console.log('Conexión exitosa a la base de datos');
    connection.release();
  }
});

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
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Acceso no autorizado');

  try {
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const [userId, userName] = decoded.split(':');
    
    db.query('SELECT id FROM login WHERE id = ? AND strNombre = ?', [userId, userName], (err, results) => {
      if (err || results.length === 0) return res.status(401).send('Token inválido');
      req.user = { id: userId, nombre: userName };
      next();
    });
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

    const filePath = `${FTP_BASE_PATH}/${req.file.originalname}`;
    const bufferStream = stream.Readable.from(req.file.buffer);
    await client.uploadFrom(bufferStream, filePath);
    client.close();

    res.send({
      message: 'Archivo subido con éxito',
      url: `${PUBLIC_URL}/${req.file.originalname}`
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al subir el archivo al FTP.');
  }
});

app.get('/list', authMiddleware, async (req, res) => {
  try {
    const client = new ftp.Client();
    await client.access(FTP_CONFIG);
    await client.cd(FTP_BASE_PATH);
    const fileList = await client.list();
    client.close();

    res.send(
      fileList.map(file => ({
        name: file.name,
        size: file.size,
        url: `${PUBLIC_URL}/${file.name}`
      }))
    );
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al listar archivos.');
  }
});

app.delete('/delete', authMiddleware, async (req, res) => {
  const { fileName } = req.body;
  if (!fileName) return res.status(400).send('File name is required.');

  try {
    const client = new ftp.Client();
    await client.access(FTP_CONFIG);
    await client.remove(`${FTP_BASE_PATH}/${fileName}`);
    client.close();

    res.send({ message: `Archivo ${fileName} eliminado correctamente.` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al eliminar archivo.');
  }
});

// --- Rutas de Películas ---
// Cambio clave: GET /movies SIN autenticación
app.get('/movies', (req, res) => {
  db.query('SELECT * FROM cine', (err, results) => {
    if (err) return res.status(500).send('Error en consulta a la base de datos.');
    res.send(results);
  });
});

// Operaciones administrativas (requieren autenticación)
app.post('/movies', authMiddleware, (req, res) => {
  const { strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen } = req.body;
  if (!strNombre || !strGenero || !strSinapsis || !strHorario || !idSala || !strImagen) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  const sanitizedStrNombre = xss(strNombre);
  const sanitizedStrGenero = xss(strGenero);
  const sanitizedStrSinapsis = xss(strSinapsis);
  const sanitizedStrHorario = xss(strHorario);
  const sanitizedStrImagen = xss(strImagen);

  const query = `INSERT INTO cine (strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen)
                VALUES (?, ?, ?, ?, ?, ?)`;
  db.query(query, [sanitizedStrNombre, sanitizedStrGenero, sanitizedStrSinapsis, sanitizedStrHorario, idSala, sanitizedStrImagen], (err, result) => {
    if (err) return res.status(500).send('Error al agregar película.');
    res.status(201).send({ message: 'Película agregada correctamente', id: result.insertId });
  });
});

app.put('/movies/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen } = req.body;
  if (!strNombre || !strGenero || !strSinapsis || !strHorario || !idSala || !strImagen) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  const sanitizedStrNombre = xss(strNombre);
  const sanitizedStrGenero = xss(strGenero);
  const sanitizedStrSinapsis = xss(strSinapsis);
  const sanitizedStrHorario = xss(strHorario);
  const sanitizedStrImagen = xss(strImagen);

  const query = `UPDATE cine SET strNombre = ?, strGenero = ?, strSinapsis = ?, strHorario = ?, idSala = ?, strImagen = ?
                WHERE id = ?`;
  db.query(query, [sanitizedStrNombre, sanitizedStrGenero, sanitizedStrSinapsis, sanitizedStrHorario, idSala, sanitizedStrImagen, id], (err) => {
    if (err) return res.status(500).send('Error al actualizar película.');
    res.send({ message: 'Película actualizada correctamente' });
  });
});

app.delete('/movies/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM cine WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).send('Error al eliminar película.');
    res.send({ message: 'Película eliminada correctamente' });
  });
});

// --- Login ---
app.post('/login', (req, res) => {
  const { strNombre, strPwd } = req.body;
  if (!strNombre || !strPwd) {
    return res.status(400).json({ error: 'Faltan credenciales' });
  }

  const query = 'SELECT id, strNombre, idEstadoUsuario, rol FROM login WHERE strNombre = ? AND strPwd = ? AND idEstadoUsuario = 1';
  db.query(query, [strNombre, strPwd], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error del servidor' });
    if (results.length === 0) return res.status(401).json({ error: 'Credenciales inválidas o usuario inactivo' });

    const usuario = results[0];
    const fakeToken = Buffer.from(`${usuario.id}:${usuario.strNombre}`).toString('base64');

    res.json({
      id: usuario.id,
      nombre: usuario.strNombre,
      rol: usuario.rol,
      token: fakeToken
    });
  });
});

// --- Ruta de prueba ---
app.get('/', (req, res) => {
  res.send('Backend funcionando. Usa /login para autenticarte.');
});

// Probar conexión al servidor FTP
(async () => {
  try {
    const client = new ftp.Client();
    await client.access(FTP_CONFIG);
    console.log('✅ Conexión exitosa al servidor FTP');
    client.close();
  } catch (error) {
    console.error('❌ Error de conexión al servidor FTP:', error);
  }
})();

// Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});