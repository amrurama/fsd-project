ALTER TABLE project_members
ADD COLUMN IF NOT EXISTS member_email VARCHAR(150);
