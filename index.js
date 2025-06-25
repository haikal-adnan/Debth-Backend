require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcrypt");

const pool = require("./db"); // PostgreSQL connection

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;

// ⛔ Stop server jika API_KEY belum didefinisikan
if (!API_KEY) {
  console.error("❌ ERROR: API_KEY is not set in the environment variables.");
  process.exit(1);
}

app.use(helmet());
app.use(cors());
app.use(express.json());

// 🔐 Middleware untuk validasi x-api-key
app.use((req, res, next) => {
  const token = req.headers["x-api-key"];
  console.log("Incoming request:", req.method, req.url);
  console.log("Received x-api-key:", token);
  console.log("Expected API_KEY:", API_KEY);

  if (token !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
});

// ✅ Route test: cek koneksi DB
app.get("/patients", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM patients");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Route dasar
app.get("/hello", (req, res) => {
  res.json({ message: "Bolehh" });
});

// ✅ Register user baru
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
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

// ✅ Login user
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

    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🚀 Mulai server
app.listen(PORT, () => {
  console.log(`✅ API running at http://localhost:${PORT}`);
});
