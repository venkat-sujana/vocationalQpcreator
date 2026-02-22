// backend/models/Syllabus.js
import mongoose from "mongoose";

const allowedGroupCodes = ["MAT", "CET", "MLT", "ET"];

const syllabusSchema = new mongoose.Schema({
  groupCode: {
    type: String,
    enum: allowedGroupCodes,
    default: "MAT",
    index: true,
  },
  board: String,
  course: String,
  courseCode: String,
  group: String,
  year: String,
  subject: String,
  subjectCode: String
});

syllabusSchema.index({ groupCode: 1, subject: 1 });

export default mongoose.model("Syllabus", syllabusSchema);
