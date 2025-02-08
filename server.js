import express from "express";
import mongoose from "mongoose";
import bodyParser from "body-parser";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import { connectDB } from "./config/db.js";
import dotenv from "dotenv";


dotenv.config();

// Connect to MongoDB
connectDB();

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// TimeSlot Schema
const timeSlotSchema = new mongoose.Schema({
    startTime: { type: String, required: true },
    endTime: { type: String, required: true },
    hrEmail: { type: String, required: true },
});
const TimeSlot = mongoose.model("TimeSlot", timeSlotSchema);

//  Middleware to Protect Routes
const protect = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

//  User Registration Route
app.post(
  "/api/auth/register",
  [
    body("email").isEmail().withMessage("Invalid email"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      user = new User({ email, password: hashedPassword });
      await user.save();

      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

//  User Login Routes
app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: "Invalid email or password" });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password" });
      }
  
      if (!process.env.JWT_SECRET) {
        return res.status(500).json({ error: "JWT secret key is missing" });
      }
  
      const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
  
      res.json({ token });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });


//  GET all time slots (Protected)
app.get("/api/timeslots", protect, async (req, res) => {
  try {
    const slots = await TimeSlot.find();
    res.json(slots);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//  POST a new time slot (Protected)
app.post("/api/timeslots", protect, async (req, res) => {
  const { startTime, endTime } = req.body;
  const hrEmail = req.user.email;

  try {
    const overlappingSlot = await TimeSlot.findOne({
      $or: [{ startTime: { $lt: endTime }, endTime: { $gt: startTime } }],
    });

    if (overlappingSlot) {
      return res.status(400).json({ message: "Time slot overlaps with another slot." });
    }

    const newSlot = new TimeSlot({ startTime, endTime, hrEmail });
    await newSlot.save();
    res.status(201).json(newSlot);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//  DELETE a time slot (Only HR who created it)
app.delete("/api/timeslots/:id", protect, async (req, res) => {
  const { userId, email } = req.user; // Get logged-in user details

  try {
    const slot = await TimeSlot.findById(req.params.id);

    if (!slot) {
      return res.status(404).json({ message: "Time slot not found" });
    }

    if (slot.hrEmail !== email) {
      return res.status(403).json({ message: "You can only delete your own slots" });
    }

    await TimeSlot.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: "Time slot deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server Started on http://localhost:${port}`);
});
