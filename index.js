const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = 3000;

app.use(express.json());


const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN bio TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN profile_picture TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN mob_no TEXT`, () => {});

app.get('/', (req, res) => {
  res.send(`
    <h2>Welcome!</h2>
    <ul>
      <li><a href="/register-form">Register</a></li>
      <li><a href="/login-form">Login</a></li>
    </ul>
  `);
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


app.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT id, username, email, bio, mob_no, profile_picture FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json(user);
  });
});

app.put('/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { email, bio, mob_no, profile_picture } = req.body;
  if (email) {
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format.' });
    }
    if (email.length > 100) {
      return res.status(400).json({ message: 'Email too long (max 100 chars).' });
    }
  }
  if (bio && bio.length > 200) {
    return res.status(400).json({ message: 'Bio too long (max 200 chars).' });
  }
  if (mob_no) {
    if (!/^\d{10,15}$/.test(mob_no)) {
      return res.status(400).json({ message: 'Mobile number must be 10-15 digits.' });
    }
  }
  if (profile_picture) {
    if (!/^https?:\/\//.test(profile_picture)) {
      return res.status(400).json({ message: 'Profile picture must be a valid URL (http or https).' });
    }
  }
  db.run('UPDATE users SET email = COALESCE(?, email), bio = COALESCE(?, bio), mob_no = COALESCE(?, mob_no), profile_picture = COALESCE(?, profile_picture) WHERE id = ?', [email, bio, mob_no, profile_picture, userId], function(err) {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (this.changes === 0) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'Profile updated successfully.' });
  });
});

app.post('/register', (req, res) => {
  const { username, password, email, bio, profile_picture, mob_no } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  const query = 'INSERT INTO users (username, password, email, bio, profile_picture, mob_no) VALUES (?, ?, ?, ?, ?, ?)';
  db.run(query, [username, hashedPassword, email || null, bio || null, profile_picture || null, mob_no || null], function(err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ message: 'Username already exists.' });
      }
      return res.status(500).json({ message: 'Database error.' });
    }
    res.status(201).json({ message: 'User registered successfully.' });
  });
});



app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }
  const query = 'SELECT * FROM users WHERE username = ?';
  db.get(query, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Database error.' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }
   
    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }
  
    const token = jwt.sign({ id: user.id, username: user.username }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token });
  });
});


app.get('/register-form', (req, res) => {
  res.send(`
    <h2>User Registration</h2>
    <form id="regForm">
      <input type="text" id="username" placeholder="Username" required /><br/>
      <input type="password" id="password" placeholder="Password" required /><br/>
      <button type="submit">Register</button>
    </form>
    <div id="result"></div>
    <script>
      document.getElementById('regForm').onsubmit = async function(e) {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const res = await fetch('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        document.getElementById('result').innerText = data.message || JSON.stringify(data);
      };
    </script>
  `);
});


app.get('/login-form', (req, res) => {
  res.send(`
    <h2>User Login</h2>
    <form id="loginForm">
      <input type="text" id="username" placeholder="Username" required /><br/>
      <input type="password" id="password" placeholder="Password" required /><br/>
      <button type="submit">Login</button>
    </form>
    <div id="loginResult"></div>
    <script>
      document.getElementById('loginForm').onsubmit = async function(e) {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const res = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        document.getElementById('loginResult').innerText = data.token ? 'JWT Token: ' + data.token : (data.message || JSON.stringify(data));
      };
    </script>
  `);
});


app.get('/profile-form', (req, res) => {
  res.send(`
    <h2>User Profile</h2>
    <div>
      <label>JWT Token: <input type="text" id="token" size="60" /></label>
      <button onclick="loadProfile()">Load Profile</button>
    </div>
    <form id="profileForm" style="display:none;">
      <div>Username: <span id="username"></span></div>
      <div>Email: <input type="email" id="email" /></div>
      <div>Bio: <input type="text" id="bio" /></div>
      <div>Mobile No: <input type="text" id="mob_no" /></div>
      <div>Profile Picture URL: <input type="text" id="profile_picture" /></div>
      <div id="profilePicPreview"></div>
      <button type="submit">Update Profile</button>
    </form>
    <div id="profileResult"></div>
    <script>
      async function loadProfile() {
        const token = document.getElementById('token').value;
        const res = await fetch('/profile', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        if (res.ok) {
          document.getElementById('profileForm').style.display = '';
          document.getElementById('username').innerText = data.username;
          document.getElementById('email').value = data.email || '';
          document.getElementById('bio').value = data.bio || '';
          document.getElementById('mob_no').value = data.mob_no || '';
          document.getElementById('profile_picture').value = data.profile_picture || '';
          document.getElementById('profilePicPreview').innerHTML = data.profile_picture ? '<img src="' + data.profile_picture + '" alt="Profile Picture" width="100" />' : '';
          document.getElementById('profileResult').innerText = '';
        } else {
          document.getElementById('profileForm').style.display = 'none';
          document.getElementById('profileResult').innerText = data.message || JSON.stringify(data);
        }
      }
      document.getElementById('profileForm').onsubmit = async function(e) {
        e.preventDefault();
        const token = document.getElementById('token').value;
        const email = document.getElementById('email').value;
        const bio = document.getElementById('bio').value;
        const mob_no = document.getElementById('mob_no').value;
        const profile_picture = document.getElementById('profile_picture').value;
        const res = await fetch('/profile', {
          method: 'PUT',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ email, bio, mob_no, profile_picture })
        });
        const data = await res.json();
        document.getElementById('profileResult').innerText = data.message || JSON.stringify(data);
        if (res.ok) loadProfile();
      };
    </script>
  `);
});


app.get('/users/:username', (req, res) => {
  const { username } = req.params;
  
  if (!/^\w{3,30}$/.test(username)) {
    return res.status(400).json({ message: 'Invalid username format.' });
  }
  db.get('SELECT id, username, bio, profile_picture, mob_no FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json(user);
  });
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

