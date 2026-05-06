CREATE INDEX IF NOT EXISTS idx_users_lower_email ON users (lower(email));
CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members (user_id);
CREATE INDEX IF NOT EXISTS idx_project_members_lower_email ON project_members (lower(member_email));
CREATE INDEX IF NOT EXISTS idx_trackers_project ON trackers (project_id);
CREATE INDEX IF NOT EXISTS idx_tracker_tasks_tracker ON tracker_tasks (tracker_id);
CREATE INDEX IF NOT EXISTS idx_tracker_tasks_assigned_to ON tracker_tasks (assigned_to);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs (entity_type, entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications (user_id, is_read, created_at DESC);
