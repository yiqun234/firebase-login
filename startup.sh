#!/bin/bash

# 设置环境变量
export PORT=3001

# 更新和安装依赖
npm install

# 检查是否已经有PM2实例在运行
if pm2 list | grep -q "firebase-login"; then
  echo "Restarting existing FIREBASE LOGIN service..."
  pm2 restart firebase-login
else
  echo "Starting new FIREBASE LOGIN service..."
  pm2 start server.js --name firebase-login
fi

# 保存PM2进程列表
pm2 save

# 输出状态
echo "FIREBASE LOGIN service is now running!"
echo "Check status with: pm2 status"
echo "View logs with: pm2 logs firebase-login"
echo "API is accessible at: http://localhost:3001"
