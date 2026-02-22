# MAT Baseline API Contract Snapshot

Captured from current server routes in `backend/api/index.js` before multi-group rollout.

## Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

## Content
- `GET /api/syllabus`
- `POST /api/topics`
- `GET /api/topics/:syllabusId`
- `POST /api/questions`
- `GET /api/questions/topic/:topicId`
- `POST /api/answerkeys`
- `GET /api/answerkeys/:questionId` (auth)

## Key paper and logs
- `GET /api/keypaper/topic/:topicId` (auth)
- `POST /api/keypaper/questions` (auth)
- `POST /api/questionpaper/download-log` (auth)
- `GET /api/download-logs` (auth)

## Admin
- `GET /api/admin/download-logs`
- `GET /api/admin/verify-panel-key`
- `GET /api/admin/question-bank/topic/:topicId`
- `POST /api/admin/question-bank`
- `GET /api/admin/question-bank/:questionId`
- `DELETE /api/admin/question-bank/:questionId`
- `POST /api/admin/question-bank/:questionId/restore`
- `PUT /api/admin/question-bank/:questionId`
- `PUT /api/admin/answerkeys/:questionId`
- `POST /api/admin/question-bank/bulk-import`
- `GET /api/admin/registration-audit-logs`

## Compatibility note
- Legacy routes default to `groupCode=MAT` when `groupCode` is not passed.
- Existing MAT clients continue to use `/api/*` routes unchanged.
