// Express.js application with SQL Injection vulnerabilities
const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Database connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'users_db'
});

connection.connect();

// Vulnerability 1: String concatenation in queries
app.get('/api/users', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

// Vulnerability 2: Template literals in SQL without parameters
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.term;
  const query = `SELECT * FROM users WHERE username LIKE '%${searchTerm}%'`;
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

// Vulnerability 3: Concatenation with user input in sequel query
app.post('/api/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // Dangerous direct use of user input
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    
    if (results.length > 0) {
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 