USE firelog;

-- Portal users table (auto-created on first login)
CREATE TABLE IF NOT EXISTS portal_users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(50) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    full_name   VARCHAR(100) DEFAULT '',
    email       VARCHAR(100) DEFAULT '',
    role        ENUM('Super Admin','IT Admin','HR Admin','Viewer') DEFAULT 'Viewer',
    status      ENUM('active','inactive') DEFAULT 'active',
    last_login  DATETIME,
    login_count INT DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Login history table (records every login attempt)
CREATE TABLE IF NOT EXISTS login_history (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(50) NOT NULL,
    role        VARCHAR(50),
    ip_address  VARCHAR(45),
    status      ENUM('success','failed') DEFAULT 'success',
    timestamp   DATETIME DEFAULT NOW(),
    INDEX idx_username  (username),
    INDEX idx_timestamp (timestamp),
    INDEX idx_status    (status)
);

-- Default admin user only
INSERT IGNORE INTO portal_users 
    (username, password, full_name, email, role, status)
VALUES
    ('admin', 'admin123', 'Super Administrator', 'admin@corp.local', 'Super Admin', 'active');