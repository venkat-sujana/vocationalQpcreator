// backend/models/Question.js
import mongoose from "mongoose";
const allowedGroupCodes = ["MAT", "CET", "MLT", "ET"];

const questionSchema = new mongoose.Schema({
  groupCode: {
    type: String,
    enum: allowedGroupCodes,
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
