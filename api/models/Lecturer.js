import mongoose from "mongoose";

const LecturerSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  collegeName: String,
  role: { type: String, default: "lecturer" }
});

export default mongoose.model("Lecturer", LecturerSchema);
