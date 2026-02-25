//backend/api/index.js

import dotenv from "dotenv";
dotenv.config();
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import express from "express";
import mongoose from "mongoose";
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
import { resolveGroupRules } from "./config/groupRules.js";
import { buildAnswerKey, buildQuestionSet, toPaperQuestion } from "./services/groupPaperService.js";

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
      token,
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

  const authHeader = String(req.get("authorization") || "").trim();
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";
  const token = req.cookies?.token || bearerToken || String(req.get("x-access-token") || "").trim();

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

const normalizeText = (value) => String(value ?? "").trim();

const normalizeParagraphs = (value) => {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item ?? "").trim())
    .filter(Boolean);
};

const DEFAULT_GROUP_CODE = "MAT";
const BASE_GROUP_CODES = ["MAT", "CET", "MLT", "ET"];
const CUSTOM_GROUP_CODE_PATTERN = /^[A-Z][A-Z0-9]{1,11}$/;
const GROUP_CODE_ALIASES = {
  "M&AT": "MAT",
  "M AT": "MAT",
  "M-AT": "MAT",
};

const GROUP_CODE_HELP_MESSAGE = `groupCode must be one of ${BASE_GROUP_CODES.join(", ")} or a custom uppercase code (2-12 letters/numbers)`;

const normalizeGroupCode = (value, defaultGroupCode = DEFAULT_GROUP_CODE) => {
  const raw = String(value || defaultGroupCode).trim().toUpperCase();
  const normalized = GROUP_CODE_ALIASES[raw] || raw;
  if (BASE_GROUP_CODES.includes(normalized)) {
    return normalized;
  }
  return CUSTOM_GROUP_CODE_PATTERN.test(normalized) ? normalized : null;
};

const resolveLegacyOrRequestedGroup = (body = {}, query = {}) => {
  const candidate = body.groupCode || query.groupCode;
  return normalizeGroupCode(candidate, DEFAULT_GROUP_CODE) || DEFAULT_GROUP_CODE;
};

const validateGroupCodeOrDefault = (body = {}, query = {}) => {
  const candidate = body.groupCode || query.groupCode;
  const normalized = normalizeGroupCode(candidate, DEFAULT_GROUP_CODE);
  if (!normalized) {
    return {
      error: {
        status: 400,
        message: GROUP_CODE_HELP_MESSAGE,
      },
    };
  }
  return { groupCode: normalized };
};

const writeRouteMetric = ({ req, routeName, groupCode, statusCode, startedAt, result }) => {
  const durationMs = Date.now() - startedAt;
  const logPayload = {
    event: "route_metric",
    route: routeName,
    method: req.method,
    path: req.originalUrl,
    groupCode: groupCode || DEFAULT_GROUP_CODE,
    statusCode,
    result,
    durationMs,
    at: new Date().toISOString(),
  };
  console.log(JSON.stringify(logPayload));
};

const parseGenerationCriteria = (payload = {}) => {
  const criteria = {};
  const optionalKeys = ["topicId", "syllabusId", "questionType", "marks", "limit", "shuffle", "includeDeleted"];
  for (const key of optionalKeys) {
    if (Object.prototype.hasOwnProperty.call(payload, key)) {
      criteria[key] = payload[key];
    }
  }
  return criteria;
};

const buildQuestionUpdate = (body = {}) => {
  const update = {};

  if (Object.prototype.hasOwnProperty.call(body, "groupCode")) {
    const groupCode = normalizeGroupCode(body.groupCode, DEFAULT_GROUP_CODE);
    if (!groupCode) {
      return { error: GROUP_CODE_HELP_MESSAGE };
    }
    update.groupCode = groupCode;
  }

  if (Object.prototype.hasOwnProperty.call(body, "questionTextEn")) {
    const questionTextEn = normalizeText(body.questionTextEn);
    if (!questionTextEn) {
      return { error: "questionTextEn cannot be empty" };
    }
    update.questionTextEn = questionTextEn;
  }

  if (Object.prototype.hasOwnProperty.call(body, "questionTextTe")) {
    const questionTextTe = normalizeText(body.questionTextTe);
    if (!questionTextTe) {
      return { error: "questionTextTe cannot be empty" };
    }
    update.questionTextTe = questionTextTe;
  }

  if (Object.prototype.hasOwnProperty.call(body, "questionType")) {
    const questionType = normalizeText(body.questionType).toUpperCase();
    if (!["SA", "LA"].includes(questionType)) {
      return { error: "questionType must be SA or LA" };
    }
    update.questionType = questionType;
  }

  if (Object.prototype.hasOwnProperty.call(body, "marks")) {
    const marks = Number(body.marks);
    if (!Number.isFinite(marks) || marks <= 0) {
      return { error: "marks must be a positive number" };
    }
    update.marks = marks;
  }

  if (Object.prototype.hasOwnProperty.call(body, "boardFrequency")) {
    const boardFrequency = Number(body.boardFrequency);
    if (!Number.isFinite(boardFrequency) || boardFrequency < 0) {
      return { error: "boardFrequency must be zero or a positive number" };
    }
    update.boardFrequency = boardFrequency;
  }

  return { update };
};

const buildQuestionCreate = (body = {}) => {
  const groupCode = normalizeGroupCode(body.groupCode, DEFAULT_GROUP_CODE);
  const syllabusId = String(body.syllabusId || "").trim();
  const topicId = String(body.topicId || "").trim();
  const questionTextEn = normalizeText(body.questionTextEn);
  const questionTextTe = normalizeText(body.questionTextTe);
  const questionType = normalizeText(body.questionType).toUpperCase();
  const marks = Number(body.marks);
  const boardFrequency = Object.prototype.hasOwnProperty.call(body, "boardFrequency")
    ? Number(body.boardFrequency)
    : 0;

  if (!groupCode) {
    return { error: GROUP_CODE_HELP_MESSAGE };
  }
  if (!mongoose.Types.ObjectId.isValid(syllabusId)) {
    return { error: "Invalid syllabusId" };
  }
  if (!mongoose.Types.ObjectId.isValid(topicId)) {
    return { error: "Invalid topicId" };
  }
  if (!questionTextEn) {
    return { error: "questionTextEn is required" };
  }
  if (!questionTextTe) {
    return { error: "questionTextTe is required" };
  }
  if (!["SA", "LA"].includes(questionType)) {
    return { error: "questionType must be SA or LA" };
  }
  if (!Number.isFinite(marks) || marks <= 0) {
    return { error: "marks must be a positive number" };
  }
  if (!Number.isFinite(boardFrequency) || boardFrequency < 0) {
    return { error: "boardFrequency must be zero or a positive number" };
  }

  return {
    payload: {
      groupCode,
      syllabusId,
      topicId,
      questionTextEn,
      questionTextTe,
      questionType,
      marks,
      boardFrequency,
    },
  };
};

const buildAnswerKeyUpdate = (body = {}) => {
  const answerPayload = body.answerKey && typeof body.answerKey === "object"
    ? body.answerKey
    : body;
  const update = {};

  if (Object.prototype.hasOwnProperty.call(answerPayload, "groupCode")) {
    const groupCode = normalizeGroupCode(answerPayload.groupCode, DEFAULT_GROUP_CODE);
    if (!groupCode) {
      return { error: GROUP_CODE_HELP_MESSAGE };
    }
    update.groupCode = groupCode;
  }

  if (Object.prototype.hasOwnProperty.call(answerPayload, "marks")) {
    const marks = Number(answerPayload.marks);
    if (!Number.isFinite(marks) || marks <= 0) {
      return { error: "answer key marks must be a positive number" };
    }
    update.marks = marks;
  }

  if (Object.prototype.hasOwnProperty.call(answerPayload, "answerParagraphsEn")) {
    update.answerParagraphsEn = normalizeParagraphs(answerPayload.answerParagraphsEn);
  }

  if (Object.prototype.hasOwnProperty.call(answerPayload, "answerParagraphsTe")) {
    update.answerParagraphsTe = normalizeParagraphs(answerPayload.answerParagraphsTe);
  }

  if (Object.prototype.hasOwnProperty.call(answerPayload, "diagramImageUrl")) {
    update.diagramImageUrl = normalizeText(answerPayload.diagramImageUrl);
  }

  if (Object.prototype.hasOwnProperty.call(answerPayload, "diagramRequired")) {
    update.diagramRequired = Boolean(answerPayload.diagramRequired);
  }

  if (Object.prototype.hasOwnProperty.call(answerPayload, "note")) {
    update.note = normalizeText(answerPayload.note);
  }

  return { update };
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
      groupCode: normalizeGroupCode(data.groupCode, DEFAULT_GROUP_CODE) || DEFAULT_GROUP_CODE,
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
app.post("/api/syllabus", async (req, res) => {
  try {
    const groupCode = resolveLegacyOrRequestedGroup(req.body);
    const payload = {
      groupCode,
      board: normalizeText(req.body?.board),
      course: normalizeText(req.body?.course),
      courseCode: normalizeText(req.body?.courseCode),
      group: normalizeText(req.body?.group),
      year: normalizeText(req.body?.year),
      subject: normalizeText(req.body?.subject),
      subjectCode: normalizeText(req.body?.subjectCode),
    };

    if (!payload.year || !payload.subject) {
      return res.status(400).json({ message: "year and subject are required" });
    }

    const syllabus = await Syllabus.create(payload);
    return res.status(201).json(syllabus);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

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
    const groupCode = resolveLegacyOrRequestedGroup(req.body);
    const topic = await Topic.create({
      ...req.body,
      groupCode,
    });
    res.status(201).json(topic);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* BULK ADD TOPICS */
app.post("/api/topics/bulk", async (req, res) => {
  try {
    const payload = Array.isArray(req.body) ? req.body : req.body?.topics;
    if (!Array.isArray(payload) || payload.length === 0) {
      return res.status(400).json({ message: "topics must be a non-empty array" });
    }

    const errors = [];
    const documents = [];

    for (let index = 0; index < payload.length; index += 1) {
      const item = payload[index] || {};
      const groupCode = resolveLegacyOrRequestedGroup(item);
      const syllabusId = String(item.syllabusId || "").trim();
      const topicName = normalizeText(item.topicName);
      const unitName = normalizeText(item.unitName);
      const unitNo = Number(item.unitNo);

      if (!mongoose.Types.ObjectId.isValid(syllabusId)) {
        errors.push({ index, message: "Invalid syllabusId" });
        continue;
      }
      if (!topicName) {
        errors.push({ index, message: "topicName is required" });
        continue;
      }
      if (!Number.isFinite(unitNo) || unitNo <= 0) {
        errors.push({ index, message: "unitNo must be a positive number" });
        continue;
      }

      const syllabus = await Syllabus.findById(syllabusId).select("groupCode").lean();
      if (!syllabus) {
        errors.push({ index, message: "syllabus not found" });
        continue;
      }
      if (syllabus.groupCode && syllabus.groupCode !== groupCode) {
        errors.push({ index, message: "syllabusId does not belong to requested groupCode" });
        continue;
      }

      documents.push({
        groupCode,
        syllabusId,
        unitNo,
        unitName,
        topicName,
      });
    }

    if (documents.length === 0) {
      return res.status(400).json({
        message: "No valid topics to insert",
        failedCount: errors.length,
        errors,
      });
    }

    const inserted = await Topic.insertMany(documents, { ordered: false });
    return res.status(201).json({
      message: "Topics bulk insert completed",
      total: payload.length,
      createdCount: inserted.length,
      failedCount: errors.length,
      errors,
      topics: inserted,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/* GET TOPICS BY SYLLABUS ID */
app.get("/api/topics/:syllabusId", async (req, res) => {
  try {
    const extractIdString = (value) => {
      if (!value) return "";
      if (typeof value === "string") return value.trim();
      if (value instanceof mongoose.Types.ObjectId) return String(value);
      if (typeof value === "object") {
        if (typeof value.$oid === "string") return value.$oid.trim();
        if (typeof value.toHexString === "function") return String(value.toHexString()).trim();
        if (typeof value.toString === "function") {
          const text = String(value.toString()).trim();
          if (text && text !== "[object Object]") return text;
        }
      }
      return "";
    };

    const buildIdMatches = (field, rawId) => {
      const id = extractIdString(rawId);
      if (!id) return [];
      const matches = [{ [field]: id }, { [`${field}.$oid`]: id }];
      if (mongoose.Types.ObjectId.isValid(id)) {
        matches.push({ [field]: new mongoose.Types.ObjectId(id) });
      }
      return matches;
    };

    const rawSyllabusId = String(req.params.syllabusId || "").trim();
    const syllabusIdQuery = buildIdMatches("syllabusId", rawSyllabusId);

    const query = {
      $or: syllabusIdQuery,
    };
    const normalizedGroup = normalizeGroupCode(req.query.groupCode);
    const applyGroupFilter = (baseQuery) => {
      if (!normalizedGroup) return baseQuery;
      if (normalizedGroup === DEFAULT_GROUP_CODE) {
        return {
          $and: [
            baseQuery,
            {
              $or: [
                { groupCode: DEFAULT_GROUP_CODE },
                { groupCode: { $exists: false } },
                { groupCode: null },
                { groupCode: "" },
              ],
            },
          ],
        };
      }
      return { ...baseQuery, groupCode: normalizedGroup };
    };

    let topics = await Topic.find(applyGroupFilter(query));

    // Fallback for duplicated/migrated syllabus documents where topics may be linked
    // to a sibling syllabus record with same subject/year/group.
    if (topics.length === 0) {
      const selectedSyllabus = await Syllabus.findOne({
        $or: buildIdMatches("_id", rawSyllabusId),
      }).lean();
      if (selectedSyllabus) {
        const siblingSyllabusQuery = {
          subject: selectedSyllabus.subject,
          year: selectedSyllabus.year,
        };
        if (selectedSyllabus.groupCode) {
          siblingSyllabusQuery.groupCode = selectedSyllabus.groupCode;
        } else if (selectedSyllabus.group) {
          siblingSyllabusQuery.group = selectedSyllabus.group;
        }

        const siblingSyllabi = await Syllabus.find(siblingSyllabusQuery).select("_id").lean();
        const siblingIds = siblingSyllabi
          .map((item) => extractIdString(item._id))
          .filter(Boolean);

        if (siblingIds.length > 0) {
          const fallbackQuery = {
            $or: siblingIds.flatMap((id) => buildIdMatches("syllabusId", id)),
          };
          topics = await Topic.find(applyGroupFilter(fallbackQuery));
        }

        // Final fallback: subject-only sibling lookup to handle legacy year/group drift.
        if (topics.length === 0 && selectedSyllabus.subject) {
          const subjectSiblings = await Syllabus.find({ subject: selectedSyllabus.subject })
            .select("_id")
            .lean();
          const subjectSiblingIds = subjectSiblings
            .map((item) => extractIdString(item._id))
            .filter(Boolean);
          if (subjectSiblingIds.length > 0) {
            const subjectFallbackQuery = {
              $or: subjectSiblingIds.flatMap((id) => buildIdMatches("syllabusId", id)),
            };
            topics = await Topic.find(applyGroupFilter(subjectFallbackQuery));
          }
        }
      }
    }

    res.json(topics);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ADD QUESTION */
app.post("/api/questions", async (req, res) => {
  try {
    console.log("Received question data:", req.body);
    const createResult = buildQuestionCreate(req.body);
    if (createResult.error) {
      return res.status(400).json({ error: createResult.error });
    }

    const [topic, syllabus] = await Promise.all([
      Topic.findById(createResult.payload.topicId).select("groupCode").lean(),
      Syllabus.findById(createResult.payload.syllabusId).select("groupCode").lean(),
    ]);

    if (!topic || !syllabus) {
      return res.status(400).json({ error: "Invalid topicId or syllabusId" });
    }

    const resolvedGroupCode = createResult.payload.groupCode || DEFAULT_GROUP_CODE;
    if (topic.groupCode && topic.groupCode !== resolvedGroupCode) {
      return res.status(400).json({ error: "topicId does not belong to requested groupCode" });
    }
    if (syllabus.groupCode && syllabus.groupCode !== resolvedGroupCode) {
      return res.status(400).json({ error: "syllabusId does not belong to requested groupCode" });
    }

    const question = await Question.create(createResult.payload);
    res.status(201).json(question);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* GET QUESTIONS BY TOPIC ID */
app.get("/api/questions/topic/:topicId", async (req, res) => {
  try {
    const query = {
      topicId: req.params.topicId,
      isDeleted: { $ne: true },
    };
    const normalizedGroup = normalizeGroupCode(req.query.groupCode);
    if (normalizedGroup) {
      query.groupCode = normalizedGroup;
    }
    const questions = await Question.find(query);
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

      const question = await Question.findById(key.questionId).select("groupCode").lean();
      if (!question) {
        return res.status(400).json({
          error: `Question not found for questionId: ${key.questionId}`,
        });
      }

      const resolvedGroupCode = normalizeGroupCode(key.groupCode, question.groupCode || DEFAULT_GROUP_CODE);
      if (!resolvedGroupCode) {
        return res.status(400).json({
          error: `Invalid groupCode for questionId: ${key.questionId}`,
        });
      }
      if (question.groupCode && question.groupCode !== resolvedGroupCode) {
        return res.status(400).json({
          error: `questionId ${key.questionId} does not belong to groupCode ${resolvedGroupCode}`,
        });
      }

      operations.push({
        updateOne: {
          filter: { questionId: key.questionId },
          update: { $set: { ...key, groupCode: resolvedGroupCode } },
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

app.get("/api/keypaper/topic/:topicId", verifyToken, async (req, res) => {
  try {
    const questions = await Question.find({
      topicId: req.params.topicId,
      isDeleted: { $ne: true },
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
        diagramImageUrl: answerKey ? answerKey.diagramImageUrl : "",
        note: answerKey ? answerKey.note : "Answer not entered yet",
      });
    }

    await logDownloadEvent(req, {
      downloadType: "keypaper_topic",
      topicId: req.params.topicId,
      questionCount: keyPaper.length,
      groupCode: questions[0]?.groupCode || DEFAULT_GROUP_CODE,
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

    const questions = await Question.find({
      _id: { $in: validIds },
      isDeleted: { $ne: true },
    });
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
        diagramImageUrl: answerKey ? answerKey.diagramImageUrl : "",
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
      groupCode: questions[0]?.groupCode || DEFAULT_GROUP_CODE,
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
      groupCode: resolveLegacyOrRequestedGroup(req.body),
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

app.post("/api/v2/papers/generate", async (req, res) => {
  const startedAt = Date.now();
  const groupValidation = validateGroupCodeOrDefault(req.body);
  if (groupValidation.error) {
    writeRouteMetric({
      req,
      routeName: "/api/v2/papers/generate",
      groupCode: req.body?.groupCode,
      statusCode: groupValidation.error.status,
      startedAt,
      result: "validation_error",
    });
    return res.status(groupValidation.error.status).json({ message: groupValidation.error.message });
  }

  const { groupCode } = groupValidation;
  const resolved = resolveGroupRules(groupCode);
  if (resolved.error) {
    writeRouteMetric({
      req,
      routeName: "/api/v2/papers/generate",
      groupCode,
      statusCode: resolved.error.status,
      startedAt,
      result: resolved.error.code,
    });
    return res.status(resolved.error.status).json({ code: resolved.error.code, message: resolved.error.message });
  }

  try {
    const criteria = parseGenerationCriteria(req.body || {});
    const questionSetResult = await buildQuestionSet(criteria, resolved.rules);
    if (questionSetResult.error) {
      writeRouteMetric({
        req,
        routeName: "/api/v2/papers/generate",
        groupCode,
        statusCode: questionSetResult.error.status,
        startedAt,
        result: questionSetResult.error.code,
      });
      return res.status(questionSetResult.error.status).json(questionSetResult.error);
    }

    const questions = questionSetResult.questionSet.map((question) => toPaperQuestion(question));

    writeRouteMetric({
      req,
      routeName: "/api/v2/papers/generate",
      groupCode,
      statusCode: 200,
      startedAt,
      result: "success",
    });

    return res.status(200).json({
      groupCode,
      paperMeta: questionSetResult.paperMeta,
      questions,
    });
  } catch (error) {
    console.error("Generate v2 question paper error:", error);
    writeRouteMetric({
      req,
      routeName: "/api/v2/papers/generate",
      groupCode,
      statusCode: 500,
      startedAt,
      result: "server_error",
    });
    return res.status(500).json({ message: "Server Error" });
  }
});

app.post("/api/v2/answer-keys/generate", verifyToken, async (req, res) => {
  const startedAt = Date.now();
  const groupValidation = validateGroupCodeOrDefault(req.body);
  if (groupValidation.error) {
    writeRouteMetric({
      req,
      routeName: "/api/v2/answer-keys/generate",
      groupCode: req.body?.groupCode,
      statusCode: groupValidation.error.status,
      startedAt,
      result: "validation_error",
    });
    return res.status(groupValidation.error.status).json({ message: groupValidation.error.message });
  }

  const { groupCode } = groupValidation;
  const resolved = resolveGroupRules(groupCode);
  if (resolved.error) {
    writeRouteMetric({
      req,
      routeName: "/api/v2/answer-keys/generate",
      groupCode,
      statusCode: resolved.error.status,
      startedAt,
      result: resolved.error.code,
    });
    return res.status(resolved.error.status).json({ code: resolved.error.code, message: resolved.error.message });
  }

  try {
    const criteria = parseGenerationCriteria(req.body || {});
    const questionSetResult = await buildQuestionSet(criteria, resolved.rules);
    if (questionSetResult.error) {
      writeRouteMetric({
        req,
        routeName: "/api/v2/answer-keys/generate",
        groupCode,
        statusCode: questionSetResult.error.status,
        startedAt,
        result: questionSetResult.error.code,
      });
      return res.status(questionSetResult.error.status).json(questionSetResult.error);
    }

    const answerKeyPayload = await buildAnswerKey(questionSetResult.questionSet, resolved.rules);

    await logDownloadEvent(req, {
      groupCode,
      downloadType: "keypaper_v2_generate",
      topicId: criteria.topicId && mongoose.Types.ObjectId.isValid(criteria.topicId) ? criteria.topicId : null,
      questionCount: answerKeyPayload.meta.questionCount,
      paperType: "answer_key",
    });

    writeRouteMetric({
      req,
      routeName: "/api/v2/answer-keys/generate",
      groupCode,
      statusCode: 200,
      startedAt,
      result: "success",
    });

    return res.status(200).json({
      groupCode,
      paperMeta: questionSetResult.paperMeta,
      secureKeyPayload: answerKeyPayload,
    });
  } catch (error) {
    console.error("Generate v2 answer key error:", error);
    writeRouteMetric({
      req,
      routeName: "/api/v2/answer-keys/generate",
      groupCode,
      statusCode: 500,
      startedAt,
      result: "server_error",
    });
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
    if (req.query.groupCode) {
      const groupCode = normalizeGroupCode(req.query.groupCode);
      if (groupCode) {
        query.groupCode = groupCode;
      }
    }

    const [logs, total] = await Promise.all([
      DownloadLog.find(query)
        .select("groupCode lecturerName email collegeName topicId date IP downloadType questionCount paperType subject examName academicYear examSession")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      DownloadLog.countDocuments(query),
    ]);

    const formattedLogs = logs.map((log) => ({
      lecturerName: log.lecturerName || "",
      groupCode: log.groupCode || DEFAULT_GROUP_CODE,
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
    if (req.query.groupCode) {
      const groupCode = normalizeGroupCode(req.query.groupCode);
      if (groupCode) {
        query.groupCode = groupCode;
      }
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
        .select("groupCode lecturerName email collegeName topicId date IP downloadType questionCount paperType subject examName academicYear examSession")
        .sort({ date: -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      DownloadLog.countDocuments(query),
    ]);

    const formattedLogs = logs.map((log) => ({
      lecturerName: log.lecturerName || "",
      groupCode: log.groupCode || DEFAULT_GROUP_CODE,
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

app.get("/api/admin/question-bank/topic/:topicId", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const { topicId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(topicId)) {
      return res.status(400).json({ message: "Invalid topicId" });
    }

    const includeDeleted = String(req.query.includeDeleted || "").trim().toLowerCase() === "true";
    const query = { topicId };
    const groupCode = normalizeGroupCode(req.query.groupCode);
    if (groupCode) {
      query.groupCode = groupCode;
    }
    if (!includeDeleted) {
      query.isDeleted = { $ne: true };
    }

    const questions = await Question.find(query)
      .sort({ createdAt: -1, _id: -1 })
      .lean();
    const questionIds = questions.map((question) => question._id);

    const answerKeys = await AnswerKey.find({ questionId: { $in: questionIds } }).lean();
    const answerKeyMap = new Map(answerKeys.map((key) => [String(key.questionId), key]));

    const response = questions.map((question) => ({
      ...question,
      answerKey: answerKeyMap.get(String(question._id)) || null,
    }));

    return res.status(200).json({ questions: response, count: response.length });
  } catch (error) {
    console.error("Fetch admin question bank by topic error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.post("/api/admin/question-bank", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const createResult = buildQuestionCreate(req.body);
    if (createResult.error) {
      return res.status(400).json({ message: createResult.error });
    }

    const [topic, syllabus] = await Promise.all([
      Topic.findById(createResult.payload.topicId).select("groupCode").lean(),
      Syllabus.findById(createResult.payload.syllabusId).select("groupCode").lean(),
    ]);
    if (!topic || !syllabus) {
      return res.status(400).json({ message: "Invalid topicId or syllabusId" });
    }
    const resolvedGroupCode = createResult.payload.groupCode || DEFAULT_GROUP_CODE;
    if (topic.groupCode && topic.groupCode !== resolvedGroupCode) {
      return res.status(400).json({ message: "topicId does not belong to requested groupCode" });
    }
    if (syllabus.groupCode && syllabus.groupCode !== resolvedGroupCode) {
      return res.status(400).json({ message: "syllabusId does not belong to requested groupCode" });
    }

    const question = await Question.create(createResult.payload);
    let answerKey = null;

    const answerKeyResult = buildAnswerKeyUpdate(req.body);
    if (answerKeyResult.error) {
      return res.status(400).json({ message: answerKeyResult.error });
    }

    if (Object.keys(answerKeyResult.update).length > 0) {
      answerKey = await AnswerKey.findOneAndUpdate(
        { questionId: question._id },
        { $set: { ...answerKeyResult.update, questionId: question._id, groupCode: question.groupCode || DEFAULT_GROUP_CODE } },
        { new: true, upsert: true },
      ).lean();
    }

    return res.status(201).json({
      message: "Question created successfully",
      question: question.toObject(),
      answerKey,
    });
  } catch (error) {
    console.error("Create admin question bank item error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.get("/api/admin/question-bank/:questionId", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const { questionId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "Invalid questionId" });
    }

    const [question, answerKey] = await Promise.all([
      Question.findById(questionId).lean(),
      AnswerKey.findOne({ questionId }).lean(),
    ]);

    if (!question) {
      return res.status(404).json({ message: "Question not found" });
    }

    return res.status(200).json({
      ...question,
      answerKey: answerKey || null,
    });
  } catch (error) {
    console.error("Fetch admin question bank item error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.delete("/api/admin/question-bank/:questionId", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const { questionId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "Invalid questionId" });
    }

    const question = await Question.findById(questionId);
    if (!question) {
      return res.status(404).json({ message: "Question not found" });
    }

    if (!question.isDeleted) {
      question.isDeleted = true;
      question.deletedAt = new Date();
      question.deletedBy = String(req.user?.email || req.user?.id || "").trim();
      await question.save();
    }

    return res.status(200).json({
      message: "Question deleted successfully",
      question: question.toObject(),
    });
  } catch (error) {
    console.error("Delete admin question bank item error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.post("/api/admin/question-bank/:questionId/restore", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const { questionId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "Invalid questionId" });
    }

    const question = await Question.findById(questionId);
    if (!question) {
      return res.status(404).json({ message: "Question not found" });
    }

    if (question.isDeleted) {
      question.isDeleted = false;
      question.deletedAt = null;
      question.deletedBy = "";
      await question.save();
    }

    return res.status(200).json({
      message: "Question restored successfully",
      question: question.toObject(),
    });
  } catch (error) {
    console.error("Restore admin question bank item error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.put("/api/admin/question-bank/:questionId", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const { questionId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "Invalid questionId" });
    }

    const questionResult = buildQuestionUpdate(req.body);
    if (questionResult.error) {
      return res.status(400).json({ message: questionResult.error });
    }

    const answerKeyResult = buildAnswerKeyUpdate(req.body);
    if (answerKeyResult.error) {
      return res.status(400).json({ message: answerKeyResult.error });
    }

    const question = await Question.findById(questionId);
    if (!question) {
      return res.status(404).json({ message: "Question not found" });
    }

    if (Object.keys(questionResult.update).length > 0) {
      Object.assign(question, questionResult.update);
      await question.save();
    }

    let answerKey = null;
    if (Object.keys(answerKeyResult.update).length > 0) {
      answerKey = await AnswerKey.findOneAndUpdate(
        { questionId },
        { $set: { ...answerKeyResult.update, questionId, groupCode: question.groupCode || DEFAULT_GROUP_CODE } },
        { new: true, upsert: true },
      ).lean();
    } else {
      answerKey = await AnswerKey.findOne({ questionId }).lean();
    }

    return res.status(200).json({
      message: "Question bank updated successfully",
      question: question.toObject(),
      answerKey: answerKey || null,
    });
  } catch (error) {
    console.error("Update admin question bank error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.put("/api/admin/answerkeys/:questionId", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const { questionId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(questionId)) {
      return res.status(400).json({ message: "Invalid questionId" });
    }

    const questionExists = await Question.exists({ _id: questionId });
    if (!questionExists) {
      return res.status(404).json({ message: "Question not found" });
    }

    const question = await Question.findById(questionId).select("groupCode").lean();
    const answerKeyResult = buildAnswerKeyUpdate(req.body);
    if (answerKeyResult.error) {
      return res.status(400).json({ message: answerKeyResult.error });
    }

    if (Object.keys(answerKeyResult.update).length === 0) {
      return res.status(400).json({ message: "No answer key fields provided" });
    }

    const answerKey = await AnswerKey.findOneAndUpdate(
      { questionId },
      { $set: { ...answerKeyResult.update, questionId, groupCode: question?.groupCode || DEFAULT_GROUP_CODE } },
      { new: true, upsert: true },
    ).lean();

    return res.status(200).json({
      message: "Answer key updated successfully",
      answerKey,
    });
  } catch (error) {
    console.error("Update admin answer key error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
});

app.post("/api/admin/question-bank/bulk-import", verifyToken, verifyAdmin, verifyAdminPanelSecret, async (req, res) => {
  try {
    const topicId = String(req.body?.topicId || "").trim();
    const syllabusId = String(req.body?.syllabusId || "").trim();
    const groupCode = normalizeGroupCode(req.body?.groupCode, DEFAULT_GROUP_CODE) || DEFAULT_GROUP_CODE;
    const items = Array.isArray(req.body?.questions) ? req.body.questions : [];

    if (!mongoose.Types.ObjectId.isValid(topicId)) {
      return res.status(400).json({ message: "Invalid topicId" });
    }
    if (!mongoose.Types.ObjectId.isValid(syllabusId)) {
      return res.status(400).json({ message: "Invalid syllabusId" });
    }
    if (items.length === 0) {
      return res.status(400).json({ message: "questions must be a non-empty array" });
    }

    const [topic, syllabus] = await Promise.all([
      Topic.findById(topicId).select("groupCode").lean(),
      Syllabus.findById(syllabusId).select("groupCode").lean(),
    ]);
    if (!topic || !syllabus) {
      return res.status(400).json({ message: "Invalid topicId or syllabusId" });
    }
    if (topic.groupCode && topic.groupCode !== groupCode) {
      return res.status(400).json({ message: "topicId does not belong to requested groupCode" });
    }
    if (syllabus.groupCode && syllabus.groupCode !== groupCode) {
      return res.status(400).json({ message: "syllabusId does not belong to requested groupCode" });
    }

    const errors = [];
    let createdCount = 0;
    let answerKeyUpserts = 0;

    for (let index = 0; index < items.length; index += 1) {
      const item = items[index] || {};
      const createResult = buildQuestionCreate({
        ...item,
        topicId,
        syllabusId,
        groupCode,
      });

      if (createResult.error) {
        errors.push({ index, message: createResult.error });
        continue;
      }

      const question = await Question.create(createResult.payload);
      createdCount += 1;

      const answerKeyResult = buildAnswerKeyUpdate(item);
      if (answerKeyResult.error) {
        errors.push({ index, message: answerKeyResult.error });
        continue;
      }

      if (Object.keys(answerKeyResult.update).length > 0) {
        await AnswerKey.findOneAndUpdate(
          { questionId: question._id },
          { $set: { ...answerKeyResult.update, questionId: question._id, groupCode: question.groupCode || groupCode } },
          { new: true, upsert: true },
        ).lean();
        answerKeyUpserts += 1;
      }
    }

    return res.status(200).json({
      message: "Bulk import completed",
      total: items.length,
      createdCount,
      answerKeyUpserts,
      failedCount: errors.length,
      errors,
    });
  } catch (error) {
    console.error("Bulk import admin question bank error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
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
