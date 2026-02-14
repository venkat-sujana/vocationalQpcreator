// backend/models/Syllabus.js
import mongoose from "mongoose";

const syllabusSchema = new mongoose.Schema({
  board: String,
  course: String,
  courseCode: String,
  group: String,
  year: String,
  subject: String,
  subjectCode: String
});
export default mongoose.model("Syllabus", syllabusSchema);
