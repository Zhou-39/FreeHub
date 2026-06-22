#!/bin/bash

echo "正在重启 Gunicorn..."

# 进入项目目录
cd /var/website/www

# 杀掉所有 Gunicorn 进程
pkill -f ".*:8000"

# 等待2秒确保进程完全退出
sleep 2

# 重新激活虚拟环境并启动
source .venv/bin/activate
nohup gunicorn --worker-class gthread --workers 1 --threads 2 --max-requests 1000 --max-requests-jitter 100 --bind 127.0.0.1:8000 app:app --timeout 120 > gunicorn.log 2>&1 &

echo "Gunicorn 重启完成！"
echo "查看日志：tail -f /var/website/www/gunicorn.log"
