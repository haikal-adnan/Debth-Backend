const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

if (process.env.NODE_ENV !== "production") {
  // Hanya di lokal
  require("dotenv").config();
}

const pool = require("./db");
const app = express();

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;

// Cek API_KEY wajib
if (!API_KEY) {
  console.log("🌍 ENV Variables:");
  console.log(process.env);
  console.error("❌ ERROR: API_KEY is not set in environment.");
  console.error("📌 Pastikan API_KEY ditambahkan di Railway → Settings → Variables");
  process.exit(1);
}

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware untuk validasi API Key
app.use((req, res, next) => {
  const token = req.headers["x-api-key"];
  console.log("Incoming request:", req.method, req.url);
  console.log("Received x-api-key:", token);
  if (token !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

// Route test
app.get("/hello", (req, res) => {
  res.json({ message: "Bolehh" });
});

// Daftar pengguna
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // Validasi input
  if (!email || !password) {
    return res.status(400).json({
      error: true,
      message: "Email and password are required"
    });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2)",
      [email, hashed]
    );
    res.status(201).json({
      error: false,
      message: "User registered successfully"
    });
  } catch (err) {
    if (err.code === "23505") {
      res.status(409).json({
        error: true,
        message: "Email already exists"
      });
    } else {
      console.error(err);
      res.status(500).json({
        error: true,
        message: "Internal Server Error"
      });
    }
  }
});



// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Buat payload dan token
    const payload = {
      id: user.id,
      email: user.email
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET || "default_secret_key", {
      expiresIn: "1d"
    });

    // Hanya kirim id dan token
    res.json({
      error: false,
      message: "Login successful",
      loginResult: {
        userId: user.id,
        token: token
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ API running at http://localhost:${PORT}`);
});
