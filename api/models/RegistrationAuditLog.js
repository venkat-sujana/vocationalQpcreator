import mongoose from "mongoose";

const registrationAuditLogSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
    },
    collegeName: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: ["success", "failed", "blocked"],
      required: true,
      trim: true,
    },
    reason: {
      type: String,
      required: true,
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
    origin: {
      type: String,
      trim: true,
    },
    path: {
      type: String,
      trim: true,
    },
    method: {
      type: String,
      trim: true,
    },
    attemptedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true },
);

registrationAuditLogSchema.index({ attemptedAt: -1 });
registrationAuditLogSchema.index({ email: 1, attemptedAt: -1 });
registrationAuditLogSchema.index({ status: 1, attemptedAt: -1 });

export default mongoose.model("RegistrationAuditLog", registrationAuditLogSchema);
