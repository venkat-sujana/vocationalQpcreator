// backend/server.js

import dotenv from "dotenv";
dotenv.config();
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import express from "express";
import { connectDB } from "./db.js";
import cors from "cors";
import Syllabus from "./models/syllabus.js";
import Topic from "./models/Topic.js";
import Question from "./models/Question.js";
import AnswerKey from "./models/AnswerKey.js";
import Lecturer from "./models/Lecturer.js";



// IMAGE UPLOAD IMPORTS  🔑
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import cloudinary from "./cloudinary.js";


const app = express();
const PORT = process.env.PORT || 5000;

console.log("JWT_SECRET:", process.env.JWT_SECRET);


const allowedOrigins = [
  
  "https://vocational-qpcreator.vercel.app"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (!allowedOrigins.includes(origin)) {
      return callback(new Error("Not allowed by CORS"));
    }

    return callback(null, true);
  },
  credentials: true
}));



app.use(cookieParser());
app.use(express.json());

connectDB(); // 🔑 DB connect here


// AUTH ROUTES
app.post("/api/auth/register", async (req, res) => {
  try {
    console.log(req.body);  // 👈 add this
    const { name, email, password, collegeName } = req.body;
    const existing = await Lecturer.findOne({ email });
    
    if (existing) {
      console.log("Email already found in DB");
      return res.status(400).json({ message: "Email already exists" });
    }




    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const lecturer = await Lecturer.create({
      name,
      email,
      password: hashedPassword,
      collegeName,
      role: "lecturer"
    });

    res.status(201).json({
      message: "Lecturer Registered Successfully ✅"
    });

  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});




//AUTH ROUTES
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
console.log("JWT_SECRET:", process.env.JWT_SECRET);

    if (!email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // 1️⃣ Check Email
    const lecturer = await Lecturer.findOne({ email });
    if (!lecturer) {
      return res.status(400).json({ message: "Invalid Email" });
    }

    // 2️⃣ Compare Password
    const isMatch = await bcrypt.compare(password, lecturer.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Password" });
    }


if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET is missing in production");
  return res.status(500).json({ message: "Server configuration error" });
}


    // 3️⃣ Generate JWT
    const token = jwt.sign(
      {
        id: lecturer._id,
        role: lecturer.role,
        name: lecturer.name,
        college: lecturer.collegeName
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // 4️⃣ Set Cookie (Production Compatible)
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,        // MUST be true for HTTPS (Vercel)
      sameSite: "none",    // REQUIRED for cross-domain
      maxAge: 24 * 60 * 60 * 1000
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        name: lecturer.name,
        email: lecturer.email,
        collegeName: lecturer.collegeName,
        role: lecturer.role
      }
    });

  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

    
   

// Logout Route

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged Out Successfully" });
});





// Middleware to verify JWT and check for lecturer role
const verifyToken = (req, res, next) => {

  console.log("Checking token...");
  console.log("Cookies:", req.cookies);

  const token = req.cookies.token;

  if (!token) {
    console.log("No token found");
    return res.status(401).json({ message: "Login Required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid Token" });
  }
};


// GET CURRENT USER INFO
app.get("/api/auth/me", verifyToken, (req, res) => {
  res.json({
    name: req.user.name,
    role: req.user.role,
    college: req.user.college
  });
});





// IMAGE UPLOAD SETUP FOR ANSWER DIAGRAMS   🔑

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "answer-diagrams",
    allowed_formats: ["jpg", "png"]
  }
});

const upload = multer({ storage });

app.post(
  "/api/upload/diagram",
  upload.single("diagram"),
  (req, res) => {
    res.json({
      imageUrl: req.file.path
    });
  }
);




/* ADD SYLLABUS */

app.get("/api/syllabus", async (req, res) => {
  try {
    const syllabus = await Syllabus.find();
    res.json(syllabus);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});





/* GET ALL SYLLABUS */
app.get("/api/syllabus", async (req, res) => {
  const syllabus = await Syllabus.find();
  res.json(syllabus);
});




/* ADD TOPIC */
app.post("/api/topics", async (req, res) => {
  try {
    console.log("Received topic data:", req.body);
    const topic = await Topic.create(req.body);
    res.status(201).json(topic);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});





/* GET TOPICS BY SYLLABUS ID */
app.get("/api/topics/:syllabusId", async (req, res) => {
  try {
    const topics = await Topic.find({
      syllabusId: req.params.syllabusId
    });
    res.json(topics);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});





/* ADD QUESTION */
app.post("/api/questions", async (req, res) => {
  try {
    console.log("Received question data:", req.body);
    const question = await Question.create(req.body);
    res.status(201).json(question);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




/* GET QUESTIONS BY TOPIC ID */
app.get("/api/questions/topic/:topicId", async (req, res) => {
  try {
    const questions = await Question.find({
      topicId: req.params.topicId
    });
    res.json(questions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



/* ADD / UPDATE ANSWER KEYS (BULK) */
app.post("/api/answerkeys", async (req, res) => {
  try {
    const answerKeys = req.body;

    if (!Array.isArray(answerKeys)) {
      return res.status(400).json({
        error: "Request body must be an array of answer keys"
      });
    }

    const operations = [];

    for (const key of answerKeys) {
      if (!mongoose.Types.ObjectId.isValid(key.questionId)) {
        return res.status(400).json({
          error: `Invalid questionId: ${key.questionId}`
        });
      }

      operations.push({
        updateOne: {
          filter: { questionId: key.questionId },
          update: { $set: key },
          upsert: true
        }
      });
    }

    const result = await AnswerKey.bulkWrite(operations);

    res.status(200).json({
      message: "Answer keys bulk upsert successful ✅",
      inserted: result.upsertedCount,
      modified: result.modifiedCount
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});






/* GET ANSWER KEY BY QUESTION ID */
app.get("/api/answerkeys/:questionId",verifyToken, async (req, res) => {
  try {
    const key = await AnswerKey.findOne({
      questionId: req.params.questionId
    });
    res.json(key);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GENERATE KEY PAPER FOR A TOPIC
import mongoose from "mongoose";

app.get("/api/keypaper/topic/:topicId",verifyToken, async (req, res) => {
  try {
    const questions = await Question.find({ topicId: req.params.topicId });

    const keyPaper = [];

    for (const q of questions) {
      const answerKey = await AnswerKey.findOne({ questionId: q._id });

      keyPaper.push({
        questionEn: q.questionTextEn,
        questionTe: q.questionTextTe,
        marks: q.marks,

        answerEn: answerKey ? answerKey.answerParagraphsEn : [],
        answerTe: answerKey ? answerKey.answerParagraphsTe : [],

        diagramRequired: answerKey ? answerKey.diagramRequired : false,
        note: answerKey ? answerKey.note : "Answer not entered yet"
      });
    }

    res.json(keyPaper);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default app;
