//backend/api/index.js

import dotenv from "dotenv";
dotenv.config();
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { connectDB } from "./db.js";
import cors from "cors";
import Syllabus from "./models/syllabus.js";
import Topic from "./models/Topic.js";
import Question from "./models/Question.js";
import AnswerKey from "./models/AnswerKey.js";
import Lecturer from "./models/Lecturer.js";
import DownloadLog from "./models/DownloadLog.js";
import RegistrationAuditLog from "./models/RegistrationAuditLog.js";

// IMAGE UPLOAD IMPORTS  🔑
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import cloudinary from "./cloudinary.js";

const app = express();
const PORT = process.env.PORT || 5000;
const isProduction = process.env.NODE_ENV === "production";

console.log("JWT_SECRET:", process.env.JWT_SECRET);

const adminEmails = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

const isAdminEmail = (email) =>
  adminEmails.includes(String(email || "").trim().toLowerCase());

const registrationSecret = String(process.env.REGISTRATION_SECRET || "").trim();
const adminPanelSecret = String(process.env.ADMIN_PANEL_SECRET || "").trim();

const allowedOrigins = [
  "https://vocational-qpcreator.vercel.app",
  "https://skr-learn-portal.netlify.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

const isAllowedOrigin = (origin) => {
  if (!origin) return true;
  if (allowedOrigins.includes(origin)) return true;

  // Allow Vercel and Netlify deployment/preview URLs.
  return (
    /^https:\/\/(?:www\.)?[a-z0-9-]+\.vercel\.app$/i.test(origin) ||
    /^https:\/\/(?:www\.)?[a-z0-9-]+\.netlify\.app$/i.test(origin)
  );
};

const corsOptions = {
  origin: function (origin, callback) {
    if (!isAllowedOrigin(origin)) {
      return callback(new Error("Not allowed by CORS"));
    }
    return callback(null, true);
  },
  credentials: true,
};

app.use(
  cors(corsOptions),
);
app.options(/.*/, cors(corsOptions));

app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  }),
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again later." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { message: "Too many auth attempts. Please try again later." },
});

const registerAttemptLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { message: "Too many failed registration attempts. Please try again later." },
  handler: (req, res, _next, options) => {
    void logRegistrationEvent(req, {
      status: "blocked",
      reason: "rate_limited",
    });
    return res.status(options.statusCode).json(options.message);
  },
});

app.use("/api", apiLimiter);

app.use(cookieParser());
app.use(express.json());

connectDB(); // 🔑 DB connect here

// AUTH ROUTES
app.post("/api/auth/register", registerAttemptLimiter, async (req, res) => {
  try {
    const { name, email, password, collegeName, secretKey } = req.body;
    const normalizedName = String(name || "").trim();
    const normalizedEmail = String(email || "").trim().toLowerCase();
    const normalizedCollegeName = String(collegeName || "").trim();
    const normalizedSecretKey = String(secretKey || "").trim();

    if (!normalizedName || !normalizedEmail || !password || !normalizedCollegeName || !normalizedSecretKey) {
      await logRegistrationEvent(req, {
        name: normalizedName,
        email: normalizedEmail,
        collegeName: normalizedCollegeName,
        status: "failed",
        reason: "missing_fields",
      });
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!registrationSecret) {
      console.error("REGISTRATION_SECRET is missing");
      await logRegistrationEvent(req, {
        name: normalizedName,
        email: normalizedEmail,
        collegeName: normalizedCollegeName,
        status: "failed",
        reason: "server_secret_missing",
      });
      return res.status(500).json({ message: "Server configuration error" });
    }

    if (normalizedSecretKey !== registrationSecret) {
      await logRegistrationEvent(req, {
        name: normalizedName,
        email: normalizedEmail,
        collegeName: normalizedCollegeName,
        status: "failed",
        reason: "invalid_secret_key",
      });
      return res.status(403).json({ message: "Invalid registration secret key" });
    }

    const existing = await Lecturer.findOne({ email: normalizedEmail });

    if (existing) {
      await logRegistrationEvent(req, {
        name: normalizedName,
        email: normalizedEmail,
        collegeName: normalizedCollegeName,
        status: "failed",
        reason: "email_already_exists",
      });
      return res.status(400).json({ message: "Email already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await Lecturer.create({
      name: normalizedName,
      email: normalizedEmail,
      password: hashedPassword,
      collegeName: normalizedCollegeName,
      role: "lecturer",
    });

    await logRegistrationEvent(req, {
      name: normalizedName,
      email: normalizedEmail,
      collegeName: normalizedCollegeName,
      status: "success",
      reason: "registered",
    });

    res.status(201).json({
      message: "Lecturer registered successfully",
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

//AUTH ROUTES
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = String(email || "").trim().toLowerCase();

    if (!normalizedEmail || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // 1️⃣ Check Email
    const lecturer = await Lecturer.findOne({ email: normalizedEmail });
    if (!lecturer) {
      return res.status(400).json({ message: "Invalid Email" });
    }

    // 2️⃣ Compare Password
    let isMatch = false;
    const storedPassword = lecturer.password;

    if (typeof storedPassword === "string" && storedPassword.startsWith("$2")) {
      isMatch = await bcrypt.compare(password, storedPassword);
    } else if (typeof storedPassword === "string") {
      // Handle legacy plaintext records and auto-upgrade hash after successful login.
      isMatch = password === storedPassword;
      if (isMatch) {
        const salt = await bcrypt.genSalt(10);
        lecturer.password = await bcrypt.hash(password, salt);
        await lecturer.save();
      }
    }
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Password" });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is missing in production");
      return res.status(500).json({ message: "Server configuration error" });
    }

    // 3️⃣ Generate JWT
    const resolvedRole = lecturer.role === "admin" || isAdminEmail(lecturer.email)
      ? "admin"
      : lecturer.role;

    const token = jwt.sign(
      {
        id: lecturer._id,
        role: resolvedRole,
        name: lecturer.name,
        email: lecturer.email,
        college: lecturer.collegeName,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" },
    );

    // 4️⃣ Set Cookie (Production Compatible)
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        name: lecturer.name,
        email: lecturer.email,
        collegeName: lecturer.collegeName,
        role: resolvedRole,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

// Logout Route

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/",
  });
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

const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== "admin" && !isAdminEmail(req.user?.email)) {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

const verifyAdminPanelSecret = (req, res, next) => {
  if (!adminPanelSecret) {
    return res.status(500).json({ message: "Admin panel secret is not configured" });
  }

  const providedSecret = String(req.get("x-admin-panel-key") || "").trim();
  if (!providedSecret || providedSecret !== adminPanelSecret) {
    return res.status(403).json({ message: "Invalid admin panel secret key" });
  }

  next();
};

const getClientIp = (req) => {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || "unknown";
};

const logRegistrationEvent = async (req, data) => {
  try {
    await RegistrationAuditLog.create({
      name: String(data.name || "").trim(),
      email: String(data.email || "").trim().toLowerCase(),
      collegeName: String(data.collegeName || "").trim(),
      status: String(data.status || "").trim(),
      reason: String(data.reason || "").trim(),
      ipAddress: getClientIp(req),
      userAgent: req.get("user-agent"),
      origin: req.get("origin"),
      path: req.originalUrl,
      method: req.method,
      attemptedAt: new Date(),
    });
  } catch (error) {
    console.error("Registration audit logging failed:", error);
  }
};

const logDownloadEvent = async (req, data) => {
  try {
    const ipAddress = getClientIp(req);
    let resolvedCollegeName = req.user?.college || req.user?.collegeName || "";
    if (!resolvedCollegeName && req.user?.id) {
      const lecturer = await Lecturer.findById(req.user.id)
        .select("collegeName")
        .lean();
      resolvedCollegeName = lecturer?.collegeName || "";
    }

    await DownloadLog.create({
      userId: req.user?.id,
      lecturerName: req.user?.name,
      email: req.user?.email,
      date: new Date(),
      IP: ipAddress,
      userName: req.user?.name,
      userRole: req.user?.role,
      collegeName: resolvedCollegeName,
      ipAddress,
      userAgent: req.get("user-agent"),
      ...data,
    });
  } catch (error) {
    console.error("Download logging failed:", error);
  }
};

// GET CURRENT USER INFO
app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const lecturer = await Lecturer.findById(req.user.id)
      .select("name email collegeName role");

    if (!lecturer) {
      return res.status(404).json({ message: "User not found" });
    }

    const resolvedRole = lecturer.role === "admin" || isAdminEmail(lecturer.email)
      ? "admin"
      : lecturer.role;

    res.json({
      name: lecturer.name,
      email: lecturer.email,
      role: resolvedRole,
      college: lecturer.collegeName,
      collegeName: lecturer.collegeName,
    });
  } catch (error) {
    console.error("Me route error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// IMAGE UPLOAD SETUP FOR ANSWER DIAGRAMS   🔑

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "answer-diagrams",
    allowed_formats: ["jpg", "png"],
  },
});

const upload = multer({ storage });

app.post("/api/upload/diagram", upload.single("diagram"), (req, res) => {
  res.json({
    imageUrl: req.file.path,
  });
});

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
      syllabusId: req.params.syllabusId,
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
      topicId: req.params.topicId,
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
        error: "Request body must be an array of answer keys",
      });
    }

    const operations = [];

    for (const key of answerKeys) {
      if (!mongoose.Types.ObjectId.isValid(key.questionId)) {
        return res.status(400).json({
          error: `Invalid questionId: ${key.questionId}`,
        });
      }

      operations.push({
        updateOne: {
          filter: { questionId: key.questionId },
          update: { $set: key },
          upsert: true,
        },
      });
    }

    const result = await AnswerKey.bulkWrite(operations);

    res.status(200).json({
      message: "Answer keys bulk upsert successful ✅",
      inserted: result.upsertedCount,
      modified: result.modifiedCount,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/* GET ANSWER KEY BY QUESTION ID */
app.get("/api/answerkeys/:questionId", verifyToken, async (req, res) => {
  try {
    const key = await AnswerKey.findOne({
      questionId: req.params.questionId,
    });
    res.json(key);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GENERATE KEY PAPER FOR A TOPIC
import mongoose from "mongoose";

app.get("/api/keypaper/topic/:topicId", verifyToken, async (req, res) => {
  try {
    const questions = await Question.find({ topicId: req.params.topicId });

    const keyPaper = [];

    for (const q of questions) {
      const answerKey = await AnswerKey.findOne({ questionId: q._id });

      keyPaper.push({
        questionId: q._id,
        questionEn: q.questionTextEn,
        questionTe: q.questionTextTe,
        marks: q.marks,

        answerEn: answerKey ? answerKey.answerParagraphsEn : [],
        answerTe: answerKey ? answerKey.answerParagraphsTe : [],

        diagramRequired: answerKey ? answerKey.diagramRequired : false,
        note: answerKey ? answerKey.note : "Answer not entered yet",
      });
    }

    await logDownloadEvent(req, {
      downloadType: "keypaper_topic",
      topicId: req.params.topicId,
      questionCount: keyPaper.length,
    });

    res.json(keyPaper);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/keypaper/questions", verifyToken, async (req, res) => {
  try {
    const { questionIds, topicId } = req.body;

    if (!Array.isArray(questionIds) || questionIds.length === 0) {
      return res.status(400).json({ error: "questionIds must be a non-empty array" });
    }

    const validIds = questionIds.filter((id) => mongoose.Types.ObjectId.isValid(id));
    if (validIds.length === 0) {
      return res.status(400).json({ error: "No valid questionIds provided" });
    }

    const questions = await Question.find({ _id: { $in: validIds } });
    const questionOrder = new Map(validIds.map((id, index) => [String(id), index]));
    questions.sort((a, b) => {
      const aIdx = questionOrder.get(String(a._id)) ?? Number.MAX_SAFE_INTEGER;
      const bIdx = questionOrder.get(String(b._id)) ?? Number.MAX_SAFE_INTEGER;
      return aIdx - bIdx;
    });

    const keyPaper = [];

    for (const q of questions) {
      const answerKey = await AnswerKey.findOne({ questionId: q._id });
      keyPaper.push({
        questionId: q._id,
        questionEn: q.questionTextEn,
        questionTe: q.questionTextTe,
        marks: q.marks,
        answerEn: answerKey ? answerKey.answerParagraphsEn : [],
        answerTe: answerKey ? answerKey.answerParagraphsTe : [],
        diagramRequired: answerKey ? answerKey.diagramRequired : false,
        note: answerKey ? answerKey.note : "Answer not entered yet",
      });
    }

    let resolvedTopicId = null;
    if (topicId && mongoose.Types.ObjectId.isValid(topicId)) {
      resolvedTopicId = topicId;
    } else if (questions.length > 0 && questions[0].topicId) {
      resolvedTopicId = questions[0].topicId;
    }

    await logDownloadEvent(req, {
      downloadType: "keypaper_questions",
      topicId: resolvedTopicId,
      questionCount: keyPaper.length,
    });

    res.json(keyPaper);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/questionpaper/download-log", verifyToken, async (req, res) => {
  try {
    const {
      paperType,
      subject,
      examName,
      academicYear,
      examSession,
      questionCount,
    } = req.body || {};

    await logDownloadEvent(req, {
      downloadType: "questionpaper_pdf",
      paperType: String(paperType || "").trim(),
      subject: String(subject || "").trim(),
      examName: String(examName || "").trim(),
      academicYear: String(academicYear || "").trim(),
      examSession: String(examSession || "").trim(),
      questionCount: Number.isFinite(Number(questionCount)) ? Number(questionCount) : 0,
    });

    return res.status(201).json({ message: "Question paper download logged" });
  } catch (error) {
    console.error("Question paper download log error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.get("/api/download-logs", verifyToken, async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const skip = (page - 1) * limit;

    const query = {
      userId: req.user.id,
    };

    if (req.query.downloadType) {
      query.downloadType = String(req.query.downloadType);
    }

    if (req.query.topicId && mongoose.Types.ObjectId.isValid(req.query.topicId)) {
      query.topicId = req.query.topicId;
    }

    const [logs, total] = await Promise.all([
      DownloadLog.find(query)
        .select("lecturerName email collegeName topicId date IP downloadType questionCount paperType subject examName academicYear examSession")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      DownloadLog.countDocuments(query),
    ]);

    const formattedLogs = logs.map((log) => ({
      lecturerName: log.lecturerName || "",
      email: log.email || "",
      collegeName: log.collegeName || "",
      topicId: log.topicId || null,
      date: log.date || null,
      IP: log.IP || "",
      downloadType: log.downloadType || "",
      questionCount: typeof log.questionCount === "number" ? log.questionCount : 0,
      paperType: log.paperType || "",
      subject: log.subject || "",
      examName: log.examName || "",
      academicYear: log.academicYear || "",
      examSession: log.examSession || "",
    }));

    res.status(200).json({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      logs: formattedLogs,
    });
  } catch (error) {
    console.error("Fetch download logs error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

app.get("/api/admin/download-logs", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const skip = (page - 1) * limit;

    const query = {};

    if (req.query.downloadType) {
      query.downloadType = String(req.query.downloadType).trim();
    }

    if (req.query.topicId && mongoose.Types.ObjectId.isValid(req.query.topicId)) {
      query.topicId = req.query.topicId;
    }

    if (req.query.email) {
      query.email = String(req.query.email).trim().toLowerCase();
    }

    if (req.query.lecturerName) {
      query.lecturerName = { $regex: String(req.query.lecturerName).trim(), $options: "i" };
    }

    if (req.query.collegeName) {
      query.collegeName = { $regex: String(req.query.collegeName).trim(), $options: "i" };
    }

    const dateQuery = {};
    if (req.query.fromDate) {
      const fromDate = new Date(req.query.fromDate);
      if (!Number.isNaN(fromDate.getTime())) {
        dateQuery.$gte = fromDate;
      }
    }
    if (req.query.toDate) {
      const toDate = new Date(req.query.toDate);
      if (!Number.isNaN(toDate.getTime())) {
        toDate.setHours(23, 59, 59, 999);
        dateQuery.$lte = toDate;
      }
    }
    if (Object.keys(dateQuery).length > 0) {
      query.date = dateQuery;
    }

    const [logs, total] = await Promise.all([
      DownloadLog.find(query)
        .select("lecturerName email collegeName topicId date IP downloadType questionCount paperType subject examName academicYear examSession")
        .sort({ date: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      DownloadLog.countDocuments(query),
    ]);

    const formattedLogs = logs.map((log) => ({
      lecturerName: log.lecturerName || "",
      email: log.email || "",
      collegeName: log.collegeName || "",
      topicId: log.topicId || null,
      date: log.date || null,
      IP: log.IP || "",
      downloadType: log.downloadType || "",
      questionCount: typeof log.questionCount === "number" ? log.questionCount : 0,
      paperType: log.paperType || "",
      subject: log.subject || "",
      examName: log.examName || "",
      academicYear: log.academicYear || "",
      examSession: log.examSession || "",
    }));

    res.status(200).json({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      logs: formattedLogs,
    });
  } catch (error) {
    console.error("Fetch admin download logs error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

app.get("/api/admin/verify-panel-key", verifyToken, verifyAdmin, verifyAdminPanelSecret, (req, res) => {
  res.status(200).json({ message: "Admin panel key verified" });
});

app.get("/api/admin/registration-audit-logs", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const skip = (page - 1) * limit;

    const query = {};

    if (req.query.status) {
      query.status = String(req.query.status).trim().toLowerCase();
    }

    if (req.query.reason) {
      query.reason = { $regex: String(req.query.reason).trim(), $options: "i" };
    }

    if (req.query.email) {
      query.email = String(req.query.email).trim().toLowerCase();
    }

    if (req.query.name) {
      query.name = { $regex: String(req.query.name).trim(), $options: "i" };
    }

    if (req.query.collegeName) {
      query.collegeName = { $regex: String(req.query.collegeName).trim(), $options: "i" };
    }

    if (req.query.ipAddress) {
      query.ipAddress = String(req.query.ipAddress).trim();
    }

    const attemptedAtQuery = {};
    if (req.query.fromDate) {
      const fromDate = new Date(req.query.fromDate);
      if (!Number.isNaN(fromDate.getTime())) {
        attemptedAtQuery.$gte = fromDate;
      }
    }
    if (req.query.toDate) {
      const toDate = new Date(req.query.toDate);
      if (!Number.isNaN(toDate.getTime())) {
        toDate.setHours(23, 59, 59, 999);
        attemptedAtQuery.$lte = toDate;
      }
    }
    if (Object.keys(attemptedAtQuery).length > 0) {
      query.attemptedAt = attemptedAtQuery;
    }

    const [logs, total] = await Promise.all([
      RegistrationAuditLog.find(query)
        .select("name email collegeName status reason ipAddress userAgent origin path method attemptedAt")
        .sort({ attemptedAt: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      RegistrationAuditLog.countDocuments(query),
    ]);

    const formattedLogs = logs.map((log) => ({
      name: log.name || "",
      email: log.email || "",
      collegeName: log.collegeName || "",
      status: log.status || "",
      reason: log.reason || "",
      ipAddress: log.ipAddress || "",
      userAgent: log.userAgent || "",
      origin: log.origin || "",
      path: log.path || "",
      method: log.method || "",
      attemptedAt: log.attemptedAt || null,
    }));

    res.status(200).json({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      logs: formattedLogs,
    });
  } catch (error) {
    console.error("Fetch registration audit logs error:", error);
    res.status(500).json({ message: "Server Error" });
  }
});

export default app;

