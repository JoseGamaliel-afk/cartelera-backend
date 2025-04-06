require('dotenv').config(); // Variables de entorno
const express = require('express');
const multer = require('multer');
const ftp = require('basic-ftp');
const mysql = require('mysql2');
const cors = require('cors');
const stream = require('stream');
const xss = require('xss');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

// === Configuración JWT ===
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_para_desarrollo';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// === Configuración MySQL ===
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Error de conexión a la base de datos:', err);
  } else {
    console.log('✅ Conexión exitosa a la base de datos');
    connection.release();
  }
});

// === Multer para subir archivos en memoria ===
const storage = multer.memoryStorage();
const upload = multer({ storage });

// === Configuración FTP ===
const FTP_CONFIG = {
  host: process.env.FTP_HOST,
  user: process.env.FTP_USER,
  password: process.env.FTP_PASSWORD,
  secure: false
};

const FTP_BASE_PATH = process.env.FTP_BASE_PATH;
const PUBLIC_URL = process.env.PUBLIC_URL;

// === Middleware JWT ===
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// === Rutas de sesión con JWT ===
app.post('/login', async (req, res) => {
  const { strNombre, strPwd } = req.body;
  if (!strNombre || !strPwd) {
    return res.status(400).json({ error: 'Faltan credenciales' });
  }

  try {
    const [results] = await db.promise().query(
      'SELECT id, strNombre, strPwd, idEstadoUsuario, rol FROM login WHERE strNombre = ? AND idEstadoUsuario = 1',
      [strNombre]
    );

    if (results.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas o usuario inactivo' });
    }

    const user = results[0];
    const passwordMatch = await bcrypt.compare(strPwd, user.strPwd);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: user.id, nombre: user.strNombre, rol: user.rol },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({ id: user.id, nombre: user.strNombre, rol: user.rol, token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// === Rutas FTP ===
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
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

app.get('/list', authenticateToken, async (req, res) => {
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

app.delete('/delete', authenticateToken, async (req, res) => {
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

// === Rutas de Películas (Protegidas) ===
app.get('/movies', authenticateToken, (req, res) => {
  db.query('SELECT * FROM cine', (err, results) => {
    if (err) return res.status(500).send('Error en consulta a la base de datos.');
    res.send(results);
  });
});

app.post('/movies', authenticateToken, (req, res) => {
  if (req.user.rol !== 'admin') return res.sendStatus(403);

  const { strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen } = req.body;
  if (!strNombre || !strGenero || !strSinapsis || !strHorario || !idSala || !strImagen) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  const query = `INSERT INTO cine (strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen)
                 VALUES (?, ?, ?, ?, ?, ?)`;

  db.query(query, [
    xss(strNombre),
    xss(strGenero),
    xss(strSinapsis),
    xss(strHorario),
    idSala,
    xss(strImagen)
  ], (err, result) => {
    if (err) return res.status(500).send('Error al agregar película.');
    res.status(201).send({ message: 'Película agregada correctamente', id: result.insertId });
  });
});

app.put('/movies/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { strNombre, strGenero, strSinapsis, strHorario, idSala, strImagen } = req.body;
  if (!strNombre || !strGenero || !strSinapsis || !strHorario || !idSala || !strImagen) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  const query = `UPDATE cine SET strNombre = ?, strGenero = ?, strSinapsis = ?, strHorario = ?, idSala = ?, strImagen = ?
                 WHERE id = ?`;

  db.query(query, [
    xss(strNombre),
    xss(strGenero),
    xss(strSinapsis),
    xss(strHorario),
    idSala,
    xss(strImagen),
    id
  ], (err) => {
    if (err) return res.status(500).send('Error al actualizar película.');
    res.send({ message: 'Película actualizada correctamente' });
  });
});

app.delete('/movies/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  if (req.user.rol !== 'admin') return res.sendStatus(403);

  db.query('DELETE FROM cine WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).send('Error al eliminar película.');
    res.send({ message: 'Película eliminada correctamente' });
  });
});

// === Verificar conexión FTP al iniciar ===
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

// === Iniciar servidor ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
