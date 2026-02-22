// backend/models/AnswerKey.js
import mongoose from "mongoose";

const allowedGroupCodes = ["MAT", "CET", "MLT", "ET"];

const answerKeySchema = new mongoose.Schema({
  groupCode: {
    type: String,
    enum: allowedGroupCodes,
    default: "MAT",
    index: true,
  },
  questionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Question",
    required: true,
    unique: true
  },

  marks: {
    type: Number,
    required: true
  },

  // 🔹 MAIN CONTENT (BILINGUAL)
  answerParagraphsEn: {
    type: [String],
    default: []
  },

  answerParagraphsTe: {
    type: [String],
    default: []
  },
  
  diagramImageUrl: {
    type: String, // 🔑 image URL
    default: ""
  },

  diagramRequired: {
    type: Boolean,
    default: false
  },

  note: String
});

answerKeySchema.index({ groupCode: 1, questionId: 1 });

export default mongoose.model("AnswerKey", answerKeySchema);
