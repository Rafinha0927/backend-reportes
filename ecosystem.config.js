module.exports = {
  apps: [{
    name: 'reports-center',
    script: 'main.py',
    cwd: '/home/ubuntu/backend-reportes',  // Ruta correcta de tu app
    args: '-w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:5000 --timeout 3600',
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
};