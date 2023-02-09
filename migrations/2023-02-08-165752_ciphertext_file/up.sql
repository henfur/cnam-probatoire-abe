-- Your SQL goes here

CREATE TABLE ciphertext_files (
    original_file_name VARCHAR(255) NOT NULL,
    ciphertext_id VARCHAR(32) NOT NULL,
    PRIMARY KEY (original_file_name, ciphertext_id)
);