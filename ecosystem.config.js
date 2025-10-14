module.exports = {
  apps: [
    {
      name: "backend-reportes",
      cwd: "/home/ubuntu/backend-reportes",
      script: "/home/ubuntu/backend-reportes/venv/bin/uvicorn",
      args: "main:app --host 0.0.0.0 --port 5000 --reload",
      interpreter: "none",
      watch: false,
      autorestart: true,
      max_restarts: 10,
      max_memory_restart: "512M",
      env: {
        PYTHONPATH: "/home/ubuntu/backend-reportes"
      },
      error_file: "/home/ubuntu/backend-reportes/logs/err.log",
      out_file: "/home/ubuntu/backend-reportes/logs/out.log",
      log_file: "/home/ubuntu/backend-reportes/logs/combined.log",
    }
  ]
}