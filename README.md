# ProjectPulse

Full-stack ProjectPulse for creating shared project workspaces, adding trackers, assigning tasks, commenting on tasks, receiving notifications, and reviewing audit history.

## What Is Included

- User signup/login with Basic auth
- Project creation with email-based sharing
- Project member lookup and assignable member lists
- Tracker creation per project, with optional template versions
- Task creation, assignment, priority, deadline, effort estimate, status updates, comments, and deletion
- Consolidated task report with filters and CSV export
- Notifications for project sharing, task assignment, status changes, and comments
- Audit logs for projects, templates, trackers, tasks, and comments
- Responsive React UI for dashboard, projects, trackers, templates, reports, and audit logs

## Database Setup

Create a PostgreSQL database named `smart_tasks`, then apply the schema:

```bash
psql -U postgres -d smart_tasks -f src/backend/db/schema.sql
```

For an existing database, apply migrations in order:

```bash
psql -U postgres -d smart_tasks -f src/backend/db/migrations/001_add_member_email.sql
psql -U postgres -d smart_tasks -f src/backend/db/migrations/002_add_access_indexes.sql
```

The backend reads these environment variables when present: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, and `JWT_SECRET`.

## Run Locally

Backend:

```bash
cd src/backend
npm install
npm start
```

Frontend:

```bash
cd src/frontend
npm install
npm start
```

The API runs on `http://localhost:4000` and the React app runs on `http://localhost:3000`.

## Verification

```bash
npm --prefix src/frontend test -- --watchAll=false
npm --prefix src/frontend run build
node --check src/backend/unified-server.js
```
