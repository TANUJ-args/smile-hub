-- Neon PostgreSQL Database Setup Script
-- Run these commands in your Neon Console SQL Editor

-- First, drop existing tables if they exist (in correct order to handle foreign key constraints)
DROP TABLE IF EXISTS patients CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    fullName VARCHAR(255),
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create patients table with proper foreign key relationship
CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    contactNo VARCHAR(20),
    email VARCHAR(255),
    patientDescription TEXT,
    treatmentStart DATE,
    totalFee NUMERIC(10,2) DEFAULT 0.00,
    paidFees NUMERIC(10,2) DEFAULT 0.00,
    patientType VARCHAR(100),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_patients_user_id ON patients(user_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_patients_name ON patients(name);

-- Insert default admin user (password: admin123)
INSERT INTO users (username, password, fullName) 
VALUES ('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'System Administrator')
ON CONFLICT (username) DO NOTHING;

-- Insert sample user (username: tanuj, password: tanuj123)
INSERT INTO users (username, password, fullName) 
VALUES ('tanuj', '$2a$10$K8gHJ9p3zOv7t8sFp9Jz4e8VnF7bN3eQ2xM4sP6tR8wY1zL5cK9bG', 'Tanuj Pavan')
ON CONFLICT (username) DO NOTHING;

-- Verify tables were created
SELECT 'Tables created successfully' as status;

-- Show table structure
\d users;
\d patients;
