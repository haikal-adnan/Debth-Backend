const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
}

const pool = require("./db");
const app = express();

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const SECRET_KEY = process.env.SECRET_KEY || '12345678901234567890123456789012'; // 32 karakter
const ALGORITHM = 'aes-256-cbc';

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

if (!API_KEY) {
    console.error("❌ ERROR: API_KEY is not set in environment.");
    process.exit(1);
}

app.use((req, res, next) => {
    const token = req.headers["x-api-key"];
    if (token !== API_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    next();
});

app.get("/hello", (req, res) => {
    res.json({ message: "Bolehh" });
});

// 🔐 Fungsi Enkripsi
function encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY), iv);
    let encrypted = cipher.update(JSON.stringify(data));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return JSON.stringify({
        iv: iv.toString('hex'),
        content: encrypted.toString('hex')
    });
}

// 🔐 Fungsi Dekripsi
function decryptData(encryptedData) {
    const payload = JSON.parse(encryptedData);
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(SECRET_KEY), Buffer.from(payload.iv, 'hex'));
    let decrypted = decipher.update(Buffer.from(payload.content, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return JSON.parse(decrypted.toString());
}

// 🔒 Register User
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: true, message: "Email and password are required" });

    try {
        const hashed = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashed]);
        res.status(201).json({ error: false, message: "User registered successfully" });
    } catch (err) {
        if (err.code === "23505") {
            res.status(409).json({ error: true, message: "Email already exists" });
        } else {
            console.error(err);
            res.status(500).json({ error: true, message: "Internal Server Error" });
        }
    }
});

// 🔒 Login User
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET || "default_secret_key", { expiresIn: "1d" });

        res.json({
            error: false,
            message: "Login successful",
            loginResult: { userId: user.id, token: token }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// 🔐 Create or Load Project (Auto Create user_activity)
app.post("/project", async (req, res) => {
    const { project_path, user_id, initial_structure } = req.body;
    if (!project_path || !user_id) return res.status(400).json({ error: true, message: "project_path and user_id are required" });

    try {
        const result = await pool.query("SELECT * FROM activity_record WHERE project_id = $1", [project_path]);
        if (result.rows.length > 0) {
            const decrypted = decryptData(result.rows[0].project_structure);
            return res.status(200).json({ record_id: result.rows[0].record_id, project_structure: decrypted });
        }

        const activityResult = await pool.query("SELECT * FROM user_activity WHERE user_id = $1", [user_id]);
        if (activityResult.rows.length === 0) {
            await pool.query(`INSERT INTO user_activity (user_id, activity_file_ids, last_update) VALUES ($1, $2, NOW())`, [user_id, []]);
        }

        const encrypted = encryptData(initial_structure);
        const insertResult = await pool.query(
            `INSERT INTO activity_record (project_id, project_structure) VALUES ($1, $2) RETURNING record_id, project_id, project_structure`,
            [project_path, encrypted]
        );

        const newRecordId = insertResult.rows[0].record_id;

        await pool.query(
            `UPDATE user_activity SET activity_file_ids = array_append(activity_file_ids, $1), last_update = NOW() WHERE user_id = $2`,
            [newRecordId, user_id]
        );

        res.status(201).json({ record_id: newRecordId, project_structure: initial_structure });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: true, message: "Internal Server Error" });
    }
});

// 🔐 Update Project
app.put("/project/:projectId", async (req, res) => {
    const { projectId } = req.params;
    const { project_structure } = req.body;

    if (!project_structure) return res.status(400).json({ error: true, message: "project_structure is required" });

    try {
        const encrypted = encryptData(project_structure);
        await pool.query(`UPDATE activity_record SET project_structure = $1 WHERE record_id = $2`, [encrypted, projectId]);

        res.status(200).json({ error: false, message: "Project structure updated successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: true, message: "Internal Server Error" });
    }
});

app.listen(PORT, () => {
    console.log(`✅ API running at http://localhost:${PORT}`);
});
