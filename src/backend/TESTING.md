# Manual Testing Plan (Postman)

> Prerequisite: start the unified backend server:
```bash
cd src/backend
npm install
npm start
```
Base URL: `http://localhost:4000`

## 1) Auth Flow
### 1.1 Signup
**POST** `/auth/signup`
```json
{
  "username": "alice",
  "password": "password123",
  "displayName": "Alice",
  "email": "alice@example.com"
}
```
**Expect:** 200 with `{ token, user }`

### 1.2 Login
**POST** `/auth/login`
```json
{
  "username": "alice",
  "password": "password123"
}
```
**Expect:** 200 with `{ token, user }`

> Save the `token` for all subsequent requests:
`Authorization: Bearer <token>`

## 2) Template Service
### 2.1 Create Template (Private)
**POST** `/templates`
```json
{
  "name": "Engineering Template",
  "description": "Sprint style tasks",
  "visibility": "PRIVATE",
  "schemaJson": { "columns": ["title", "status", "priority"] }
}
```
**Expect:** 200 with `template` and `version`.

### 2.2 Create Template (Public)
**POST** `/templates`
```json
{
  "name": "Public QA Template",
  "visibility": "PUBLIC",
  "schemaJson": { "columns": ["title", "deadline"] }
}
```

### 2.3 List Templates
**GET** `/templates`
**Expect:** list includes your private templates + public templates.

### 2.4 Add Template Version
**POST** `/templates/{templateId}/versions`
```json
{ "schemaJson": { "columns": ["title", "status", "notes"] } }
```
**Expect:** version increment.

## 3) Project Service
### 3.1 Create Project (with members)
**POST** `/projects`
```json
{
  "name": "Project Apollo",
  "description": "Example project",
  "templateId": "<optional-template-id>",
  "members": ["<userId-of-member>"]
}
```
**Expect:** project returned.

### 3.2 List Projects
**GET** `/projects`
**Expect:** projects owned or member of.

## 4) Tracker Service
### 4.1 Create Tracker
**POST** `/trackers`
```json
{
  "projectId": "<project-id>",
  "templateVersionId": "<template-version-id>",
  "name": "Sprint 1"
}
```

### 4.2 Create Task
**POST** `/tasks`
```json
{
  "trackerId": "<tracker-id>",
  "title": "Implement login",
  "description": "Basic JWT auth",
  "status": "TODO",
  "priority": true,
  "deadline": "2026-05-01T10:00:00Z",
  "effortEstimate": 5,
  "assignedTo": "<user-id>"
}
```

### 4.3 Update Task (with note)
**PUT** `/tasks/{taskId}`
```json
{
  "status": "IN_PROGRESS",
  "priority": true,
  "note": "Started work",
  "effortEstimate": 8
}
```
**Expect:** task updated + entry in `task_update_history`.

### 4.4 Consolidated Report
**GET** `/tasks/report`
**Expect:** tasks assigned to you or visible through project membership.

## 5) Notification Service
### 5.1 Create Notification
**POST** `/notifications`
```json
{
  "userId": "<user-id>",
  "message": "Task nearing deadline"
}
```

### 5.2 List Notifications
**GET** `/notifications`
**Expect:** user notifications ordered by created_at desc.

## 6) Audit Service
### 6.1 Create Audit Entry
**POST** `/audit`
```json
{
  "entityType": "tracker_task",
  "entityId": "<task-id>",
  "action": "UPDATE",
  "previousValue": {"status": "TODO"},
  "newValue": {"status": "IN_PROGRESS"},
  "note": "Owner updated status"
}
```

### 6.2 View Audit Logs
**GET** `/audit?entityType=tracker_task&entityId=<task-id>`
**Expect:** entries sorted by timestamp.
