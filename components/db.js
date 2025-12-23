const mysql = require("mysql2");
require('dotenv').config(); 

// Create the pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'db',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    multipleStatements: true,
    waitForConnections: true,
    connectionLimit: 10, 
    queueLimit: 0,
    enableKeepAlive: true
});


pool.getConnection((err, connection) => {
    if (err) {
        console.error("❌ Database connection failed! Check if MySQL is ready.");
        console.error("Details:", err.message);

    } else {
        console.log("✅ Successfully connected to the MySQL database.");
        connection.release();
    }
});

module.exports = pool.promise();