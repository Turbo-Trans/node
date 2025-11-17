const mysql = require("mysql2");
let dotenv = require('dotenv').config(); 
var con = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    multipleStatements: true,
    waitForConnections: true,
    connectionLimit: 50,
    queueLimit: 0,
    enableKeepAlive: true
});

con.getConnection((err, connection) => {
    if (err) throw err;
    connection.release();
});
module.exports = con;