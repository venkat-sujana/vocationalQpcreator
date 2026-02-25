import mongoose from "mongoose";

const groupCodePattern = /^[A-Z][A-Z0-9]{1,11}$/;

const downloadLogSchema = new mongoose.Schema(
  {
    groupCode: {
      type: String,
      validate: {
        validator: (value) => groupCodePattern.test(String(value || "").trim().toUpperCase()),
        message: "groupCode must be 2-12 uppercase letters/numbers",
      },
      default: "MAT",
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Lecturer",
    },
    lecturerName: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
    },
    topicId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Topic",
    },
    date: {
      type: Date,
      default: Date.now,
    },
    IP: {
      type: String,
      trim: true,
    },
    // Backward-compatible fields kept for existing consumers.
    userName: {
      type: String,
      trim: true,
    },
    userRole: {
      type: String,
      trim: true,
    },
    collegeName: {
      type: String,
      trim: true,
    },
    downloadType: {
      type: String,
      required: true,
      trim: true,
    },
    questionCount: {
      type: Number,
      default: 0,
    },
    paperType: {
      type: String,
      trim: true,
    },
    subject: {
      type: String,
      trim: true,
    },
    examName: {
      type: String,
      trim: true,
    },
    academicYear: {
      type: String,
      trim: true,
    },
    examSession: {
      type: String,
      trim: true,
    },
    ipAddress: {
      type: String,
      trim: true,
    },
    userAgent: {
      type: String,
      trim: true,
    },
  },
  { timestamps: true },
);

downloadLogSchema.index({ userId: 1, createdAt: -1 });
downloadLogSchema.index({ downloadType: 1, createdAt: -1 });
downloadLogSchema.index({ email: 1, date: -1 });
downloadLogSchema.index({ groupCode: 1, createdAt: -1 });

export default mongoose.model("DownloadLog", downloadLogSchema);
