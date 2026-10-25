CREATE DATABASE IF NOT EXISTS cedac CHARACTER SET utf8mb4;
USE cedac;

CREATE TABLE data_owners (
  owner_id INT AUTO_INCREMENT PRIMARY KEY,
  owner_name VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(150) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  key_salt VARCHAR(64) NOT NULL,
  pub_key TEXT NOT NULL,
  enc_priv TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending'
);

CREATE TABLE end_users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  user_name VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(150) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  key_salt VARCHAR(64) NOT NULL,
  pub_key TEXT NOT NULL,
  enc_priv TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending'
);

CREATE TABLE files (
  file_id INT AUTO_INCREMENT PRIMARY KEY,
  owner_id INT NOT NULL,
  file_name VARCHAR(200) NOT NULL,
  encrypted_key TEXT NOT NULL,          -- key list [Kf, Kr1..Krn] wrapped for the owner
  layer_count INT NOT NULL DEFAULT 0,   -- onion layers added by the cloud
  checksum VARCHAR(64),
  is_deleted TINYINT NOT NULL DEFAULT 0,
  FOREIGN KEY (owner_id) REFERENCES data_owners(owner_id)
);

CREATE TABLE file_chunks (
  chunk_id INT AUTO_INCREMENT PRIMARY KEY,
  file_id INT NOT NULL,
  chunk_index INT NOT NULL,
  encrypted_chunk LONGBLOB NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(file_id)
);

CREATE TABLE access_policies (
  policy_id INT AUTO_INCREMENT PRIMARY KEY,
  file_id INT NOT NULL,
  allowed_user_id INT NOT NULL,
  privilege VARCHAR(20) NOT NULL DEFAULT 'read',
  expiration_time DATETIME NULL,
  wrapped_keys TEXT NOT NULL,           -- key list wrapped for this user's public key
  active TINYINT NOT NULL DEFAULT 1,
  UNIQUE KEY uq_file_user (file_id, allowed_user_id),
  FOREIGN KEY (file_id) REFERENCES files(file_id),
  FOREIGN KEY (allowed_user_id) REFERENCES end_users(user_id)
);

CREATE TABLE access_requests (
  request_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  file_id INT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  FOREIGN KEY (user_id) REFERENCES end_users(user_id),
  FOREIGN KEY (file_id) REFERENCES files(file_id)
);

CREATE TABLE audit_logs (
  log_id INT AUTO_INCREMENT PRIMARY KEY,
  owner_id INT, user_id INT, file_id INT,
  action_type VARCHAR(50),
  action_message TEXT,
  elapsed_ms BIGINT DEFAULT 0,
  bytes_processed BIGINT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
