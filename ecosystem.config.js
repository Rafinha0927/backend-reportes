module.exports = {
  apps: [
    {
      name: "backend-reportes",
      cwd: "/home/ubuntu/backend-reportes",

      // Ejecuta Uvicorn como módulo de Python (no usamos venv)
      interpreter: "python3",
      interpreter_args: "-m",
      script: "uvicorn",
      args: "main:app --host 0.0.0.0 --port 5000",

      // Producción: sin --reload
      watch: false,
      autorestart: true,
      max_restarts: 10,
      max_memory_restart: "512M",
    }
  ]
}