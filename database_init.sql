CREATE USER 'mam'@'%' IDENTIFIED BY 'mam';
CREATE DATABASE IF NOT EXISTS mam;
GRANT ALL PRIVILEGES ON mam.* TO 'mam'@'%';
FLUSH PRIVILEGES;