import mongoose from "mongoose";
const MONGO_URL = "mongodb+srv://mechtelugu:chintu@cluster0.umllpps.mongodb.net/question_paper_db";

export const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URL);
    console.log("MongoDB connected successfully  Database Name: question_paper_db ✅");
  } catch (err) {
    console.error("DB error ❌", err);
  }
};
