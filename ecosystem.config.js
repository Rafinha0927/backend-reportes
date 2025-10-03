module.exports = {
  apps: [
    {
      name: "backend-reportes",
      cwd: "/home/ubuntu/backend-reportes",

      // Ejecuta Uvicorn como módulo de Python (no usamos venv)
      interpreter: "python3",
      script: "main.py",

      // Producción: sin --reload
      watch: false,
      autorestart: true,
      max_restarts: 10,
      max_memory_restart: "512M",
    }
  ]
}