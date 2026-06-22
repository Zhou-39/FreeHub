#!/bin/bash

echo "正在重启 Gunicorn..."

# 进入项目目录
cd /var/website/ide

# 杀掉所有 Gunicorn 进程
pkill -f "gunicorn.*:8001"

# 等待2秒确保进程完全退出
sleep 2

# 重新激活虚拟环境并启动
source .venv/bin/activate
nohup gunicorn --worker-class eventlet --workers 1 --bind 0.0.0.0:8001 --timeout 120 --max-requests 500 --max-requests-jitter 50 app:app > "/var/website/ide/logs/gunicorn.log" 2>&1 &

echo "Gunicorn 重启完成！"
echo "查看日志：tail -f /var/website/ide/logs/gunicorn.log"
