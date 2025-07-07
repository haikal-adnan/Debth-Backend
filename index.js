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

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// Cek API_KEY wajib
if (!API_KEY) {
  console.log("🌍 ENV Variables:");
  console.log(process.env);
  console.error("❌ ERROR: API_KEY is not set in environment.");
  console.error("📌 Pastikan API_KEY ditambahkan di Railway → Settings → Variables");
  process.exit(1);
}


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

    const payload = {
      id: user.id,
      email: user.email
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET || "default_secret_key", {
      expiresIn: "1d"
    });

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


// Cek atau buat project baru dan auto-create user_activity jika belum ada
app.post("/project", async (req, res) => {
  const { project_path, user_id, initial_structure } = req.body;

  if (!project_path || !user_id) {
    return res.status(400).json({
      error: true,
      message: "project_path and user_id are required"
    });
  }

  try {
    // 1. Cek apakah project sudah ada
    const result = await pool.query(
      "SELECT * FROM activity_record WHERE project_id = $1",
      [project_path]
    );

    if (result.rows.length > 0) {
      return res.status(200).json({
        record_id: result.rows[0].record_id,
        project_structure: result.rows[0].project_structure
      });
    }

    // 2. Cek apakah user_activity sudah ada
    const activityResult = await pool.query(
      "SELECT * FROM user_activity WHERE user_id = $1",
      [user_id]
    );

    // 3. Kalau user_activity belum ada → buatkan
    if (activityResult.rows.length === 0) {
      await pool.query(
        `INSERT INTO user_activity (user_id, activity_file_ids, last_update)
         VALUES ($1, $2, NOW())`,
        [user_id, []]
      );
    }

    // 4. Buat project baru
    const project_structure = initial_structure || { project_name: project_path, folders: [] };

    const insertResult = await pool.query(
      `INSERT INTO activity_record (project_id, project_structure)
       VALUES ($1, $2) RETURNING record_id, project_id, project_structure`,
      [project_path, project_structure]
    );

    const newRecordId = insertResult.rows[0].record_id;

    // 5. Masukkan record_id ke activity_file_ids
    await pool.query(
      `UPDATE user_activity
       SET activity_file_ids = array_append(activity_file_ids, $1), last_update = NOW()
       WHERE user_id = $2`,
      [newRecordId, user_id]
    );

    res.status(201).json({
      record_id: insertResult.rows[0].record_id, // <== gunakan ini
      project_structure: insertResult.rows[0].project_structure
    });


  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal Server Error"
    });
  }
});


// Update project structure
app.put("/project/:projectId", async (req, res) => {
  const { projectId } = req.params; // Ini adalah record_id (UUID)
  const { project_structure } = req.body;

  if (!project_structure) {
    return res.status(400).json({
      error: true,
      message: "project_structure is required"
    });
  }

  try {
    await pool.query(
      `UPDATE activity_record SET project_structure = $1 WHERE record_id = $2`,
      [project_structure, projectId]
    );

    res.status(200).json({
      error: false,
      message: "Project structure updated successfully"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal Server Error"
    });
  }
});
