# Multi-Group Backend Rollout (MAT/CET/MLT/ET)

## Environment flags

Add these in backend environment configuration:

```env
ENABLE_GROUP_CET=false
ENABLE_GROUP_MLT=false
ENABLE_GROUP_ET=false
```

`MAT` is always enabled for backward compatibility.

## Backfill existing documents

Run once before enabling new groups in production:

```bash
npm run backfill:group-code
```

This sets missing `groupCode` to `MAT` for:
- `syllabus`
- `topics`
- `questions`
- `answerkeys`
- `downloadlogs`

## New v2 APIs

### POST `/api/v2/papers/generate`

Request:

```json
{
  "groupCode": "CET",
  "topicId": "topicObjectId",
  "syllabusId": "syllabusObjectId",
  "questionType": "SA",
  "marks": 2,
  "limit": 20,
  "shuffle": true
}
```

Response:
- `200`: `{ groupCode, paperMeta, questions }`
- `400`: invalid group/filter
- `403`: group disabled by feature flags
- `422`: insufficient question pool (`missingRules` included)

### POST `/api/v2/answer-keys/generate`

Auth required (`verifyToken` middleware).

Request:

```json
{
  "groupCode": "CET",
  "topicId": "topicObjectId",
  "limit": 20
}
```

Response:
- `200`: `{ groupCode, paperMeta, secureKeyPayload }`
- `400`: invalid input
- `403`: group disabled
- `422`: insufficient question pool

## Rollout order

1. Deploy code with flags off (`CET/MLT/ET` false).
2. Run backfill script.
3. Stage enable CET -> validate.
4. Stage enable MLT -> validate.
5. Stage enable ET -> validate.
6. Repeat same order in production.
7. Rollback by setting group flag to `false`.
