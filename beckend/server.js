const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt"); // For password hashing
const cors = require("cors"); // For CORS
require("dotenv").config(); // For environment variables

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(bodyParser.json());
app.use(cors()); // Enable CORS

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI; // Use environment variable
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("Error connecting to MongoDB:", err));

// User Schema and Model
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullname: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Routes
// 1. Register
app.post("/register", async (req, res) => {
    const { email, password, fullname } = req.body;

    if (!email || !password || !fullname) {
        return res.status(400).json({ message: "All fields are required." });
    }

    try {
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(409).json({ message: "User already exists." });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ email, password: hashedPassword, fullname });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully." });
    } catch (err) {
        res.status(500).json({ message: "Error registering user.", error: err.message });
    }
});

// 2. Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        // Compare passwords
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        res.status(200).json({ message: "Login successful." });
    } catch (err) {
        res.status(500).json({ message: "Error logging in.", error: err.message });
    }
});

// 3. Forgot Password
app.post("/forgotpassword", async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ message: "Email and new password are required." });
    }

    try {
        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ message: "Password updated successfully." });
    } catch (err) {
        res.status(500).json({ message: "Error updating password.", error: err.message });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
