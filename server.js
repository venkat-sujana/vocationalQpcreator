// backend/server.js
import express from "express";
import cors from "cors";
import { connectDB } from "./db.js";

import Syllabus from "./models/syllabus.js";
import Topic from "./models/Topic.js";
import Question from "./models/Question.js";
import AnswerKey from "./models/AnswerKey.js";


// IMAGE UPLOAD IMPORTS  🔑
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import cloudinary from "./cloudinary.js";



const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors());
app.use(express.json());

connectDB(); // 🔑 DB connect here


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

app.post("/api/syllabus", async (req, res) => {
  try {
    console.log("Received syllabus data:", req.body);
    const syllabus = await Syllabus.create(req.body);
    res.status(201).json(syllabus);
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



/* ADD ANSWER KEY */
app.post("/api/answerkeys", async (req, res) => {
  try {
    console.log("Received answer key data:", req.body);
    const key = await AnswerKey.create(req.body);
    res.status(201).json(key);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/* GET ANSWER KEY BY QUESTION ID */
app.get("/api/answerkeys/:questionId", async (req, res) => {
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

app.get("/api/keypaper/topic/:topicId", async (req, res) => {
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


app.listen(PORT, () => {
  console.log("server is running on port", PORT);
});
