import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB connected successfully ✅");
  } catch (err) {
    console.error("DB error ❌", err);
    process.exit(1);
  }
};
