CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password VARCHAR(200) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user'
);


CREATE TABLE report_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL
);


CREATE TABLE report (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    file_path VARCHAR(200),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    anonymous_owner_id INTEGER,
    status_id INTEGER NOT NULL,
    deleted_by_admin BOOLEAN DEFAULT 0,

    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (anonymous_owner_id) REFERENCES user(id),
    FOREIGN KEY (status_id) REFERENCES report_status(id)
);


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
    anonymous BOOLEAN NOT NULL DEFAULT 0,
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
