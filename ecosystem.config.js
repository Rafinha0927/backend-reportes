module.exports = {
  apps: [{
    name: 'reports-center',
    script: 'main.py',
    cwd: "C:/Users/Not me/Downloads/Github super pro/backend-reportes-1",
    interpreter: 'python',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 5000
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true
  }]
}
;