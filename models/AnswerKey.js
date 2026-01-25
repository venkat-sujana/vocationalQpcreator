// backend/models/AnswerKey.js
import mongoose from "mongoose";

const answerKeySchema = new mongoose.Schema({
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

export default mongoose.model("AnswerKey", answerKeySchema);
