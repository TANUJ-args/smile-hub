module.exports = {
  apps: [{
    name: 'smile-hub',
    script: './server.js',
    cwd: 'C:/PROJECTS/DENTAL-P2/home',
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    }
  }]
};

