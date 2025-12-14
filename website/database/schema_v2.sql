ALTER TABLE report ADD COLUMN anonymous_owner_id INTEGER;
ALTER TABLE report ADD COLUMN deleted_by_admin BOOLEAN DEFAULT 0;

CREATE TABLE admin_comment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    comment TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES report(id),
    FOREIGN KEY (admin_id) REFERENCES user(id)
);

CREATE TABLE student_reply (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    user_id INTEGER,
    anonymous BOOLEAN DEFAULT 0,
    reply TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES report(id),
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE notification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    sender_id INTEGER,
    user_id INTEGER,
    FOREIGN KEY (sender_id) REFERENCES user(id),
    FOREIGN KEY (user_id) REFERENCES user(id)
);