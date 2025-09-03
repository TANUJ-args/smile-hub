module.exports = {
  apps: [{
    name: 'smile-hub',
    script: './server.js',
    instances: 'max',
    exec_mode: 'cluster',
    watch: false,
    autorestart: true,
    max_memory_restart: '512M',
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: process.env.PORT || 3000
    },
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    error_file: './logs/error.log',
    out_file: './logs/output.log',
    combine_logs: true,
    time: true
  }]
};

