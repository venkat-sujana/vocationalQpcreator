// backend/models/Question.js
import mongoose from "mongoose";
const groupCodePattern = /^[A-Z][A-Z0-9]{1,11}$/;

const questionSchema = new mongoose.Schema({
  groupCode: {
    type: String,
    validate: {
      validator: (value) => groupCodePattern.test(String(value || "").trim().toUpperCase()),
      message: "groupCode must be 2-12 uppercase letters/numbers",
    },
    default: "MAT",
    index: true,
  },
  syllabusId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Syllabus",
    required: true
  },
  topicId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Topic",
    required: true
  },

  // 🔹 NEW (Bilingual)
  questionTextEn: {
    type: String,
    required: true
  },
  questionTextTe: {
    type: String,
    required: true
  },

  questionType: {
    type: String,
    enum: ["SA", "LA"],
    required: true
  },

  marks: {
    type: Number,
    required: true
  },


  boardFrequency: {
    type: Number,
    default: 0
  },

  isDeleted: {
    type: Boolean,
    default: false,
    index: true,
  },

  deletedAt: {
    type: Date,
    default: null,
  },

  deletedBy: {
    type: String,
    default: "",
  }
}, { timestamps: true });

questionSchema.index({ groupCode: 1, topicId: 1 });

export default mongoose.model("Question", questionSchema);
