module.exports = {
  apps: [{
    name: 'reports-center',
    script: 'main.py',
    args: '-m uvicorn main:app --host 0.0.0.0 --port 5000 --reload',
    cwd: '/home/ubuntu/backend-reportes',
    instances: 1,
    autorestart: true,
    watch: true,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 5000,
      PYTHONPATH: '/home/ubuntu/backend-reportes',
      PYTHONUNBUFFERED: 1
    },
    error_file: '/home/ubuntu/backend-reportes/logs/err.log',
    out_file: '/home/ubuntu/backend-reportes/logs/out.log',
    log_file: '/home/ubuntu/backend-reportes/logs/combined.log',
    time: true
  }]
};