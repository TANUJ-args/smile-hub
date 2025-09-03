# Smile Hub Deployment Guide

This guide provides instructions for deploying the Smile Hub dental practice management application to a production environment.

## Prerequisites

- Node.js v18 or later
- PostgreSQL database (Neon PostgreSQL recommended)
- A platform for hosting Node.js applications (Render, Heroku, DigitalOcean, etc.)

## Environment Variables

Set the following environment variables in your hosting platform:

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/dbname?sslmode=require` |
| `SESSION_SECRET` | Secret for session encryption | A long random string |
| `NODE_ENV` | Environment setting | `production` |
| `PORT` | Port for the application (often set by hosting provider) | `3000` |

## Deployment Steps

### 1. Prepare Your Database

Ensure your PostgreSQL database is set up with SSL enabled. When using Neon PostgreSQL:

1. Create a new project in Neon
2. Create a database named `smiledental`
3. Create a role with password
4. Get the connection string from the Neon dashboard

### 2. Deploy to Render

1. Create a new Web Service in Render
2. Connect your GitHub repository
3. Configure the service:
   - **Name**: smile-hub
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
4. Add environment variables mentioned above
5. Deploy the service

### 3. Database Initialization

The application will automatically initialize the database tables on first run.

### 4. Verify Deployment

1. Visit the `/health` endpoint to check the status of the application
2. Verify that you can register, login, and manage patients
3. Check server logs for any errors

## Troubleshooting

### Database Connection Issues

- Verify that the `DATABASE_URL` is correct
- Ensure SSL settings are enabled
- Check database logs for connection attempts

### Session Problems

- Verify that the session table was created
- Check `SESSION_SECRET` is set correctly
- Review logs for session-related errors

### Security Concerns

- Ensure `NODE_ENV` is set to `production`
- Check that SSL/HTTPS is enabled
- Verify that CORS is properly configured

## Monitoring

- Use the `/health` endpoint to check application status
- Consider setting up uptime monitoring
- Review server logs periodically

## Backup Strategy

- Set up regular database backups
- Store application code in a version control system
- Document any manual configurations

---

For additional support, please open an issue in the GitHub repository.
