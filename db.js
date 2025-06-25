const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // diperlukan untuk koneksi SSL di Railway
  }
});

module.exports = pool;
