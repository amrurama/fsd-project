# ProjectPulse Backend

The unified Express API runs on `http://localhost:4000`.

```bash
npm install
npm start
```

## Core Endpoints

Auth and users:

- `POST /auth/signup`
- `POST /auth/login`
- `GET /users/me`
- `GET /users?search=alice`

Templates:

- `GET /templates`
- `GET /templates/:templateId/versions`
- `POST /templates`
- `POST /templates/:templateId/versions`

Projects:

- `GET /projects`
- `GET /projects/:projectId`
- `GET /projects/:projectId/members`
- `POST /projects`
- `PUT /projects/:projectId`
- `DELETE /projects/:projectId`

Trackers and tasks:

- `GET /projects/:projectId/trackers`
- `POST /trackers`
- `PUT /trackers/:trackerId`
- `DELETE /trackers/:trackerId`
- `GET /trackers/:trackerId/tasks`
- `GET /tasks/report`
- `POST /tasks`
- `PUT /tasks/:taskId`
- `DELETE /tasks/:taskId`
- `GET /tasks/:taskId/comments`
- `POST /tasks/:taskId/comments`

Notifications and audit:

- `GET /notifications`
- `POST /notifications`
- `PUT /notifications/:notificationId/read`
- `PUT /notifications/read-all`
- `GET /audit`
- `GET /audit?entityType=tracker_task&entityId=<task-id>`
- `POST /audit`

## Existing Database Migration

```sql
ALTER TABLE project_members
ADD COLUMN IF NOT EXISTS member_email VARCHAR(150);
```

Then run:

```bash
psql -U postgres -d smart_tasks -f db/migrations/002_add_access_indexes.sql
```
