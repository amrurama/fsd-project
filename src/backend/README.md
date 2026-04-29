# Smart Task Orchestrator Backend (Unified Server)

## Run locally
```bash
cd src/backend
npm install
npm start
```
The unified API runs on `http://localhost:4000`.

## Key Endpoints

### Auth
- `POST /auth/signup`
- `POST /auth/login`

### Templates
- `GET /templates`
- `POST /templates`
- `POST /templates/:templateId/versions`

### Projects
- `GET /projects`
- `POST /projects`

### Trackers & Tasks
- `POST /trackers`
- `POST /tasks`
- `PUT /tasks/:taskId`
- `GET /tasks/report`

### Notifications
- `GET /notifications`
- `POST /notifications`

### Audit Logs
- `GET /audit?entityType=...&entityId=...`
- `POST /audit`

## Migration Note (existing DBs)
If you already created the database before adding `member_email`, run:
```sql
ALTER TABLE project_members
ADD COLUMN IF NOT EXISTS member_email VARCHAR(150);
```
