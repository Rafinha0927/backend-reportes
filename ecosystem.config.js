module.exports = {
  apps: [{
    name: 'reports-center',
    script: 'main.py',
    cwd: '/home/ubuntu/backend-reportes',
    interpreter: '/home/ubuntu/backend-reportes/venv/bin/python',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 5000,
      PYTHONPATH: '/home/ubuntu/backend-reportes'
    },
    error_file: '/home/ubuntu/backend-reportes/logs/err.log',
    out_file: '/home/ubuntu/backend-reportes/logs/out.log',
    log_file: '/home/ubuntu/backend-reportes/logs/combined.log',
    time: true
  }]
}
;