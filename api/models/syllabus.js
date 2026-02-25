// backend/models/Syllabus.js
import mongoose from "mongoose";

const groupCodePattern = /^[A-Z][A-Z0-9]{1,11}$/;

const syllabusSchema = new mongoose.Schema({
  groupCode: {
    type: String,
    validate: {
      validator: (value) => groupCodePattern.test(String(value || "").trim().toUpperCase()),
      message: "groupCode must be 2-12 uppercase letters/numbers",
    },
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
