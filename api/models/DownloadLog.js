import mongoose from "mongoose";

const downloadLogSchema = new mongoose.Schema(
  {
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

export default mongoose.model("DownloadLog", downloadLogSchema);
