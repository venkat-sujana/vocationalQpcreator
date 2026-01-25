import mongoose from "mongoose";

const topicSchema = new mongoose.Schema({
  syllabusId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Syllabus",
    required: true
  },
  unitNo: Number,
  unitName: String,
  topicName: String
});

export default mongoose.model("Topic", topicSchema);
