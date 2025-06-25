const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcrypt");

require("dotenv").config();

const pool = require("./db"); 

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;

app.use(helmet());
app.use(cors());
app.use(express.json());

// Middleware Auth
app.use((req, res, next) => {
  const token = req.headers["x-api-key"];
  if (token !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  console.log("Incoming request:", req.method, req.url);
  console.log("x-api-key:", req.headers['x-api-key']);
  next();
});

// Test: ambil semua data dari tabel "patients"
app.get("/patients", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM patients");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Endpoint dasar
app.get("/hello", (req, res) => {
  res.json({ message: "Bolehh" });
});

app.listen(PORT, () => {
  console.log(`API running at http://localhost:${PORT}`);
});


// Register user baru
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Hash password sebelum simpan
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    if (err.code === "23505") {
      res.status(409).json({ error: "Username or email already exists" });
    } else {
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Berhasil login
    res.json({ message: "Login successful", user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
