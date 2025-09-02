// Database Connection Test Script
// Run this with: node test-connection.js

require('dotenv').config();
const { Pool } = require('pg');

async function testConnection() {
  console.log('Testing Neon PostgreSQL Connection...');
  console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
  console.log('NODE_ENV:', process.env.NODE_ENV);
  
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable is not set');
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000, // Increase timeout to 10 seconds
  });

  try {
    // Test basic connection
    console.log('Attempting to connect...');
    const client = await pool.connect();
    console.log('✅ Connection successful!');

    // Test basic query
    console.log('Testing basic query...');
    const result = await client.query('SELECT NOW() as current_time, version()');
    console.log('✅ Query successful!');
    console.log('Current time:', result.rows[0].current_time);
    console.log('PostgreSQL version:', result.rows[0].version.split(' ')[0] + ' ' + result.rows[0].version.split(' ')[1]);

    // Check if our tables exist
    console.log('Checking for existing tables...');
    const tablesResult = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name
    `);
    
    if (tablesResult.rows.length > 0) {
      console.log('✅ Existing tables found:');
      tablesResult.rows.forEach(row => {
        console.log('  -', row.table_name);
      });
    } else {
      console.log('⚠️  No tables found. Run the neon-setup.sql script first.');
    }

    // Test user table if it exists
    try {
      const userCount = await client.query('SELECT COUNT(*) as count FROM users');
      console.log('✅ Users table accessible. User count:', userCount.rows[0].count);
    } catch (error) {
      console.log('⚠️  Users table not accessible:', error.message);
    }

    // Test patient table if it exists
    try {
      const patientCount = await client.query('SELECT COUNT(*) as count FROM patients');
      console.log('✅ Patients table accessible. Patient count:', patientCount.rows[0].count);
    } catch (error) {
      console.log('⚠️  Patients table not accessible:', error.message);
    }

    client.release();
    console.log('✅ Connection test completed successfully!');
    
  } catch (error) {
    console.error('❌ Connection test failed:');
    console.error('Error:', error.message);
    console.error('Code:', error.code);
    
    if (error.code === 'ENOTFOUND') {
      console.error('This usually means the hostname in DATABASE_URL is incorrect');
    } else if (error.code === 'ECONNREFUSED') {
      console.error('This usually means the database server is not accessible');
    } else if (error.code === '28P01') {
      console.error('This usually means invalid credentials in DATABASE_URL');
    }
    
  } finally {
    await pool.end();
    process.exit(0);
  }
}

testConnection();
