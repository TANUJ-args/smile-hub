-- Drop existing tables (in correct order for foreign key constraints)
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

-- Create patients table
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
