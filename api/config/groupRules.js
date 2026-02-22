const GROUP_CODES = ["MAT", "CET", "MLT", "ET"];
const GROUP_CODE_ALIASES = {
  "M&AT": "MAT",
  "M AT": "MAT",
  "M-AT": "MAT",
};

const GROUP_RULES = {
  MAT: {
    groupCode: "MAT",
    sections: [],
    marksPerQuestion: 1,
    negativeMark: 0,
    difficultyMix: {},
    isEnabled: true,
  },
  CET: {
    groupCode: "CET",
    sections: [],
    marksPerQuestion: 1,
    negativeMark: 0,
    difficultyMix: {},
    isEnabled: true,
  },
  MLT: {
    groupCode: "MLT",
    sections: [],
    marksPerQuestion: 1,
    negativeMark: 0,
    difficultyMix: {},
    isEnabled: true,
  },
  ET: {
    groupCode: "ET",
    sections: [],
    marksPerQuestion: 1,
    negativeMark: 0,
    difficultyMix: {},
    isEnabled: true,
  },
};

const toBoolean = (value, defaultValue = false) => {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return defaultValue;
};

const getFlagEnabledMap = () => ({
  MAT: true,
  CET: toBoolean(process.env.ENABLE_GROUP_CET, false),
  MLT: toBoolean(process.env.ENABLE_GROUP_MLT, false),
  ET: toBoolean(process.env.ENABLE_GROUP_ET, false),
});

const resolveGroupRules = (rawGroupCode) => {
  const normalizedRaw = String(rawGroupCode || "").trim().toUpperCase();
  const groupCode = GROUP_CODE_ALIASES[normalizedRaw] || normalizedRaw;
  if (!GROUP_CODES.includes(groupCode)) {
    return {
      error: {
        status: 400,
        code: "UNKNOWN_GROUP",
        message: `Unsupported groupCode: ${rawGroupCode}`,
      },
    };
  }

  const baseRules = GROUP_RULES[groupCode];
  const flagEnabledMap = getFlagEnabledMap();
  const isEnabled = Boolean(baseRules.isEnabled) && Boolean(flagEnabledMap[groupCode]);

  if (!isEnabled) {
    return {
      error: {
        status: 403,
        code: "GROUP_DISABLED",
        message: `${groupCode} is disabled for this environment`,
      },
    };
  }

  return {
    rules: {
      ...baseRules,
      groupCode,
      isEnabled,
      flagEnabled: flagEnabledMap[groupCode],
    },
  };
};

export { GROUP_CODES, GROUP_RULES, resolveGroupRules };
