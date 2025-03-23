const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const { Pool } = require("pg");
dotenv.config();

// const app = express();

const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
};

const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
};

app.post("/register", async (req, res) => {
    const { id,username, password , email } = req.body;

    // ตรวจสอบค่าที่รับมาว่าไม่เป็น undefined หรือ null
    if (!password || typeof password !== "string") {
        console.log("Password is required and must be a string");
        return res.status(400).json({ error: "Password is required and must be a string" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        await pool.query("INSERT INTO members (id,username, password_hash,email) VALUES ($1,$2,$3,$4)", [id,username, hashedPassword,email]);
        res.json({ message: "User registered successfully" });
    } catch (error) {
        console.log("error",error);
        res.status(500).json({ message: "Error registering user", error });
    }

    // console.log("ssss");
    // res.json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const user = result.rows[0];
        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const accessToken = generateAccessToken({ username });
        const refreshToken = generateRefreshToken({ username });
        await pool.query("INSERT INTO refresh_tokens (token) VALUES ($1)", [refreshToken]);
        res.json({ accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ message: "Error logging in", error });
    }
});

app.post("/token", async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(403).json({ message: "Forbidden" });
    try {
        const result = await pool.query("SELECT * FROM refresh_tokens WHERE token = $1", [token]);
        if (result.rows.length === 0) return res.status(403).json({ message: "Forbidden" });
        jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            const accessToken = generateAccessToken({ username: user.username });
            res.json({ accessToken });
        });
    } catch (error) {
        res.status(500).json({ message: "Error validating token", error });
    }
});

app.post("/logout", async (req, res) => {
    const { token } = req.body;
    try {
        await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [token]);
        res.json({ message: "Logged out successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error logging out", error });
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.get("/protected", authenticateToken, (req, res) => {
    res.json({ message: "This is a protected route", user: req.user });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
