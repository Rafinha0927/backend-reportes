module.exports = {
  apps: [
    {
      name: "backend-reportes",
      cwd: "/home/ubuntu/backend-reportes",

      // Ejecuta uvicorn como módulo de Python para usar el venv
      interpreter: "/home/ubuntu/backend-reportes/.venv/bin/python",
      interpreter_args: "-m",
      script: "uvicorn",
      args: "main:app --host 0.0.0.0 --port 5000",

      watch: false,
      autorestart: true,
      max_restarts: 10,
      max_memory_restart: "512M",
    }
  ]
}