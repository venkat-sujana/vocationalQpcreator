import mongoose from "mongoose";
import Question from "../models/Question.js";
import AnswerKey from "../models/AnswerKey.js";

const normalizeQuestionFilters = (criteria = {}) => {
  const filters = {};

  if (criteria.topicId) {
    const topicId = String(criteria.topicId).trim();
    if (!mongoose.Types.ObjectId.isValid(topicId)) {
      return { error: "Invalid topicId" };
    }
    filters.topicId = topicId;
  }

  if (criteria.syllabusId) {
    const syllabusId = String(criteria.syllabusId).trim();
    if (!mongoose.Types.ObjectId.isValid(syllabusId)) {
      return { error: "Invalid syllabusId" };
    }
    filters.syllabusId = syllabusId;
  }

  if (criteria.questionType) {
    const questionType = String(criteria.questionType).trim().toUpperCase();
    if (!["SA", "LA"].includes(questionType)) {
      return { error: "questionType must be SA or LA" };
    }
    filters.questionType = questionType;
  }

  if (Object.prototype.hasOwnProperty.call(criteria, "marks")) {
    const marks = Number(criteria.marks);
    if (!Number.isFinite(marks) || marks <= 0) {
      return { error: "marks must be a positive number" };
    }
    filters.marks = marks;
  }

  return { filters };
};

const shuffleArray = (items) => {
  const arr = [...items];
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
};

const toPaperQuestion = (question) => ({
  questionId: question._id,
  topicId: question.topicId,
  syllabusId: question.syllabusId,
  questionEn: question.questionTextEn,
  questionTe: question.questionTextTe,
  questionType: question.questionType,
  marks: question.marks,
  boardFrequency: question.boardFrequency ?? 0,
});

const buildQuestionSet = async (criteria = {}, rules) => {
  const parsed = normalizeQuestionFilters(criteria);
  if (parsed.error) {
    return { error: { status: 400, code: "INVALID_FILTER", message: parsed.error } };
  }

  const includeDeleted = String(criteria.includeDeleted || "").trim().toLowerCase() === "true";
  const query = {
    groupCode: rules.groupCode,
    ...parsed.filters,
  };
  if (!includeDeleted) {
    query.isDeleted = { $ne: true };
  }

  const limitRaw = criteria.limit;
  let limit = null;
  if (limitRaw !== undefined && limitRaw !== null && String(limitRaw).trim() !== "") {
    const parsedLimit = Number(limitRaw);
    if (!Number.isInteger(parsedLimit) || parsedLimit <= 0) {
      return { error: { status: 400, code: "INVALID_LIMIT", message: "limit must be a positive integer" } };
    }
    limit = parsedLimit;
  }

  const shouldShuffle = String(criteria.shuffle || "").trim().toLowerCase() === "true";

  let questions = await Question.find(query).lean();
  if (shouldShuffle) {
    questions = shuffleArray(questions);
  } else {
    questions.sort((a, b) => {
      const aFreq = Number.isFinite(a.boardFrequency) ? a.boardFrequency : 0;
      const bFreq = Number.isFinite(b.boardFrequency) ? b.boardFrequency : 0;
      if (aFreq !== bFreq) {
        return bFreq - aFreq;
      }
      return new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime();
    });
  }

  const availableCount = questions.length;
  if (limit && availableCount < limit) {
    return {
      error: {
        status: 422,
        code: "INSUFFICIENT_QUESTION_POOL",
        message: `Requested ${limit} questions but only ${availableCount} matched`,
        missingRules: {
          requestedCount: limit,
          availableCount,
          groupCode: rules.groupCode,
          filters: parsed.filters,
        },
      },
    };
  }

  if (limit) {
    questions = questions.slice(0, limit);
  }

  const totalMarks = questions.reduce((sum, item) => sum + (Number(item.marks) || 0), 0);

  return {
    questionSet: questions,
    paperMeta: {
      groupCode: rules.groupCode,
      generatedAt: new Date().toISOString(),
      questionCount: questions.length,
      totalMarks,
      criteria: {
        ...parsed.filters,
        includeDeleted,
        limit,
        shuffle: shouldShuffle,
      },
      sections: rules.sections || [],
      marksPerQuestion: rules.marksPerQuestion,
      negativeMark: rules.negativeMark,
      difficultyMix: rules.difficultyMix || {},
    },
  };
};

const buildAnswerKey = async (questionSet = [], rules) => {
  const questionIds = questionSet.map((question) => question._id);
  const answerKeys = await AnswerKey.find({
    groupCode: rules.groupCode,
    questionId: { $in: questionIds },
  }).lean();

  const answerKeyMap = new Map(answerKeys.map((item) => [String(item.questionId), item]));
  const keyItems = questionSet.map((question) => {
    const key = answerKeyMap.get(String(question._id));
    return {
      questionId: question._id,
      questionEn: question.questionTextEn,
      questionTe: question.questionTextTe,
      marks: question.marks,
      answerEn: key?.answerParagraphsEn || [],
      answerTe: key?.answerParagraphsTe || [],
      diagramRequired: key?.diagramRequired || false,
      diagramImageUrl: key?.diagramImageUrl || "",
      note: key?.note || "Answer not entered yet",
      hasAnswerKey: Boolean(key),
    };
  });

  return {
    keyItems,
    meta: {
      groupCode: rules.groupCode,
      generatedAt: new Date().toISOString(),
      questionCount: keyItems.length,
      answeredCount: keyItems.filter((item) => item.hasAnswerKey).length,
      unansweredCount: keyItems.filter((item) => !item.hasAnswerKey).length,
    },
  };
};

export { buildQuestionSet, buildAnswerKey, toPaperQuestion };
