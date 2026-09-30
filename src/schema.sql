CREATE TABLE cnrl_enrolments (
    community_id TEXT NOT NULL,
    user_id TEXT NOT NULL CHECK (length(user_id) = 36),
    subject TEXT NOT NULL CHECK (length(subject) > 0),
    expires_day INTEGER CHECK (expires_day IS NULL OR expires_day > 0),
    cleanup INTEGER NOT NULL CHECK (cleanup IN (0, 1)),
    payload TEXT NOT NULL,
    PRIMARY KEY (community_id, user_id),
    UNIQUE (community_id, subject)
) WITHOUT ROWID;
CREATE INDEX cnrl_expiry ON cnrl_enrolments (community_id, expires_day, user_id);
CREATE INDEX cnrl_cleanup ON cnrl_enrolments (community_id, cleanup, user_id);
