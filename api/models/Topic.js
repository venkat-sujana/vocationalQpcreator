//backend/ models/Topic.js
import mongoose from "mongoose";

const groupCodePattern = /^[A-Z][A-Z0-9]{1,11}$/;

const topicSchema = new mongoose.Schema({
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
  unitNo: Number,
  unitName: String,
  topicName: String
});

topicSchema.index({ groupCode: 1, syllabusId: 1 });

export default mongoose.model("Topic", topicSchema);
