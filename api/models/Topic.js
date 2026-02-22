//backend/ models/Topic.js
import mongoose from "mongoose";

const allowedGroupCodes = ["MAT", "CET", "MLT", "ET"];

const topicSchema = new mongoose.Schema({
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
  unitNo: Number,
  unitName: String,
  topicName: String
});

topicSchema.index({ groupCode: 1, syllabusId: 1 });

export default mongoose.model("Topic", topicSchema);
