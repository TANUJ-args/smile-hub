-- Additional SQL Commands for Neon Console Troubleshooting
-- Run these after the main setup script if you need to debug issues

-- 1. Check if tables exist
SELECT table_name, table_schema 
FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;

-- 2. Check table structure
SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'users' 
ORDER BY ordinal_position;

SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'patients' 
ORDER BY ordinal_position;

-- 3. Check for existing data
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as patient_count FROM patients;

-- 4. View sample data
SELECT id, username, email, fullname, createdat FROM users LIMIT 5;
SELECT id, name, contactno, treatmentstart, user_id FROM patients LIMIT 5;

-- 5. Check foreign key constraints
SELECT
    tc.constraint_name, 
    tc.table_name, 
    kcu.column_name, 
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name 
FROM information_schema.table_constraints AS tc 
JOIN information_schema.key_column_usage AS kcu
    ON tc.constraint_name = kcu.constraint_name
    AND tc.table_schema = kcu.table_schema
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = tc.constraint_name
    AND ccu.table_schema = tc.table_schema
WHERE tc.constraint_type = 'FOREIGN KEY';

-- 6. Test date insertion (run this to test date format)
-- This should work without errors if date handling is correct
DO $$
BEGIN
    -- Test date insertion
    INSERT INTO users (username, password, fullName) 
    VALUES ('test_user_' || extract(epoch from now()), 'test', 'Test User') 
    RETURNING id;
    
    -- Clean up test user
    DELETE FROM users WHERE username LIKE 'test_user_%';
    
    RAISE NOTICE 'Date test completed successfully';
END $$;

-- 7. If you need to reset everything completely
-- DROP SCHEMA public CASCADE;
-- CREATE SCHEMA public;
-- GRANT ALL ON SCHEMA public TO public;

-- 8. Grant permissions (if needed)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO neondb_owner;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO neondb_owner;

-- 9. Check current database connection info
SELECT current_database(), current_user, version();
