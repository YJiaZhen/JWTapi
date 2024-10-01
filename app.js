require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const secretKey = process.env.SECRET_KEY;

app.use(express.json());

// 設置 PostgreSQL 連接
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: 5433,
});


// 註冊路由
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // 檢查用戶名是否已存在
    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: '用戶名已存在' });
    }

    // 加密密碼
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 創建新用戶
    const newUser = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, created_at',
      [username, hashedPassword]
    );

    res.status(201).json({ 
      message: '用戶創建成功', 
      userId: newUser.rows[0].id,
      createdAt: newUser.rows[0].created_at
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '伺服器錯誤' });
  }
});

// 登入路由
app.post('/signin', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign(
        { id: user.id, username: user.username, created_at: user.created_at }, 
        secretKey, 
        { expiresIn: '1h' }
      );
      res.json({ token });
    } else {
      res.status(401).json({ message: '身份驗證失敗' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '伺服器錯誤' });
  }
});

// 中間件：驗證 JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 受保護的路由
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ 
    message: '這是受保護的資源', 
    user: {
      id: req.user.id,
      username: req.user.username,
      created_at: req.user.created_at
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`伺服器運行在 http://localhost:${PORT}`);
});