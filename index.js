const express = require("express");
const app = express();
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

if (process.env.NODE_ENV !== "production") {
  // Hanya di lokal
  require("dotenv").config();
}

const pool = require("./db");

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Token required" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "default_secret_key");

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

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

    // 3. Kalau user_activity belum ada → buatkan dengan default values
    if (activityResult.rows.length === 0) {
      await pool.query(
        `INSERT INTO user_activity (
          user_id,
          activity_file_ids,
          is_online,
          is_on_vsc,
          focus_duration_vsc,
          total_duration_vsc,
          last_update
        )
        VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [
          user_id,
          [],          // activity_file_ids kosong
          0,           // is_online: false → gunakan float 0
          0,           // is_on_vsc: 0
          0,           // focus_duration_vsc: 0
          0            // total_duration_vsc: 0
        ]
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

    // 5. Tambahkan record_id ke activity_file_ids
    await pool.query(
      `UPDATE user_activity
       SET activity_file_ids = array_append(activity_file_ids, $1), last_update = NOW()
       WHERE user_id = $2`,
      [newRecordId, user_id]
    );

    res.status(201).json({
      record_id: insertResult.rows[0].record_id,
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

app.put("/activity", async (req, res) => {
  const { user_id, is_online, is_on_vsc, focus_duration_vsc, total_duration_vsc } = req.body;

  if (!user_id) {
    return res.status(400).json({
      error: true,
      message: "user_id is required"
    });
  }

  try {
    await pool.query(
      `UPDATE user_activity
       SET
         is_online = $1,
         is_on_vsc = $2,
         focus_duration_vsc = $3,
         total_duration_vsc = $4,
         last_update = NOW()
       WHERE user_id = $5`,
      [
        is_online,
        is_on_vsc,
        focus_duration_vsc,
        total_duration_vsc,
        user_id
      ]
    );

    res.status(200).json({ message: "User activity updated" });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Internal Server Error"
    });
  }
});




// GET /summary/activity → List project dan activity_context
app.get("/summary/activity", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    const userActivityRes = await pool.query(
      `SELECT * FROM user_activity WHERE user_id = $1`,
      [userId]
    );

    if (userActivityRes.rows.length === 0) {
      return res.status(404).json({ error: true, message: "No activity found" });
    }

    const activity = userActivityRes.rows[0];
    const fileIds = activity.activity_file_ids;

    const projectResult = await pool.query(
      `SELECT record_id, project_id, project_structure FROM activity_record WHERE record_id = ANY($1)`,
      [fileIds]
    );

    const projects = projectResult.rows.map((row) => {
      const pathParts = row.project_id.split("\\");
      const lastSegment = pathParts[pathParts.length - 1];
      return {
        project_id: row.project_id,
        project_name: lastSegment,
        record_id: row.record_id
      };
    });

    const activity_context = {
      activity_file_ids: activity.activity_file_ids,
      is_online: !!activity.is_online,
      is_on_vsc: !!activity.is_on_vsc,
      focus_duration_vsc: activity.focus_duration_vsc,
      total_duration_vsc: activity.total_duration_vsc
    };

    res.json({
      error: false,
      message: "Data Loaded Success",
      projects,
      activity_context
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, message: "Internal Server Error" });
  }
});


// GET /summary/project/:recordId → Detail struktur + summary
app.get("/summary/project/:recordId", authenticate, async (req, res) => {
  const { recordId } = req.params;

  try {
    const result = await pool.query(
      `SELECT * FROM activity_record WHERE record_id = $1`,
      [recordId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Project not found" });
    }

    const { project_structure, project_id } = result.rows[0];
    const files = [];
    let total_keystrokes_count = 0;
    let total_file_switch_count = 0;
    let total_idle_duration = 0;
    let total_all_duration = 0;

    const traverse = (folders, parentPath = "") => {
      folders.forEach((folder) => {
        const currentPath = parentPath ? `${parentPath}/${folder.folder_name}` : folder.folder_name;

        folder.files.forEach((file) => {
          files.push({
            file_name: file.file_name,
            folder_path: currentPath,
            idle_duration: file.idle_duration,
            total_duration: file.total_duration,
            keystrokes_count: file.keystrokes_count,
            file_switch_count: file.file_switch_count
          });

          total_keystrokes_count += file.keystrokes_count;
          total_file_switch_count += file.file_switch_count;
          total_idle_duration += file.idle_duration;
          total_all_duration += file.total_duration;
        });

        if (folder.folders && folder.folders.length > 0) {
          traverse(folder.folders, currentPath);
        }
      });
    };

    traverse(project_structure.folders);

    const summary = {
      total_keystrokes_count,
      total_file_switch_count,
      total_idle_duration,
      total_all_duration,
      total_focus_duration: total_all_duration - total_idle_duration
    };

    const pathParts = project_id.split("\\");
    const lastSegment = pathParts[pathParts.length - 1];

    res.json({ project_id, project_name: lastSegment, summary, files });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// // Start server
// app.listen(PORT, () => {
//   console.log(`✅ API running at http://localhost:${PORT}`);
// });

setInterval(async () => {
  try {
    const result = await pool.query(`
      UPDATE user_activity
      SET is_online = 0,
          is_on_vsc = 0
      WHERE last_update < NOW() - INTERVAL '30 seconds'
    `);
    if (result.rowCount > 0) {
      console.log(`[Auto-Reset] ${result.rowCount} user_activity set to offline`);
    }
  } catch (err) {
    console.error("[Auto-Reset Error]", err);
  }
}, 10_000); // Cek setiap 10 detik

module.exports = app;