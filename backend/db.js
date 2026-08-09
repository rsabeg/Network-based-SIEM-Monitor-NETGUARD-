// NETGUARD - MySQL connection pool
// One shared pool that server.js (and later the auth routes) pulls
// connections from, instead of opening a new one per request.

const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: '127.0.0.1',
  port: 3306,
  user: 'root',        // XAMPP default - change if you set a different MySQL user
  password: '',        // XAMPP default is blank - change if you set a password
  database: 'netguard',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
