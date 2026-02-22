import dotenv from "dotenv";
import mongoose from "mongoose";
import Syllabus from "../api/models/syllabus.js";
import Topic from "../api/models/Topic.js";
import Question from "../api/models/Question.js";
import AnswerKey from "../api/models/AnswerKey.js";
import DownloadLog from "../api/models/DownloadLog.js";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI;

const run = async () => {
  if (!MONGO_URI) {
    throw new Error("MONGO_URI is required");
  }

  await mongoose.connect(MONGO_URI);

  const updates = await Promise.all([
    Syllabus.updateMany(
      { $or: [{ groupCode: { $exists: false } }, { groupCode: null }, { groupCode: "" }] },
      { $set: { groupCode: "MAT" } },
    ),
    Topic.updateMany(
      { $or: [{ groupCode: { $exists: false } }, { groupCode: null }, { groupCode: "" }] },
      { $set: { groupCode: "MAT" } },
    ),
    Question.updateMany(
      { $or: [{ groupCode: { $exists: false } }, { groupCode: null }, { groupCode: "" }] },
      { $set: { groupCode: "MAT" } },
    ),
    AnswerKey.updateMany(
      { $or: [{ groupCode: { $exists: false } }, { groupCode: null }, { groupCode: "" }] },
      { $set: { groupCode: "MAT" } },
    ),
    DownloadLog.updateMany(
      { $or: [{ groupCode: { $exists: false } }, { groupCode: null }, { groupCode: "" }] },
      { $set: { groupCode: "MAT" } },
    ),
  ]);

  const [syllabus, topics, questions, answerKeys, downloadLogs] = updates;
  console.log("Backfill completed:");
  console.log(`Syllabus updated: ${syllabus.modifiedCount}`);
  console.log(`Topics updated: ${topics.modifiedCount}`);
  console.log(`Questions updated: ${questions.modifiedCount}`);
  console.log(`AnswerKeys updated: ${answerKeys.modifiedCount}`);
  console.log(`DownloadLogs updated: ${downloadLogs.modifiedCount}`);
};

run()
  .catch((error) => {
    console.error("Backfill failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
