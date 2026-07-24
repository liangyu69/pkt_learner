# PKT-Learner

A minimal command-line tool for learning computer network principles by capturing and analyzing network packets.

## Purpose

This tool is designed for **learning purposes only**. It helps you understand how network protocols work by showing you the raw packet headers in real-time. No fancy UI, no complex analysis—just the essential fields you need to see what's happening on the wire.

## Features

- Lightweight and minimal
- Real-time packet capture and display
- Focus on key header fields
- Easy to extend for different protocols
- **Completely self-contained** — no external dependencies besides libpcap


## 📡 项目亮点

在学习TCP协议时，我使用本工具抓包验证了连接释放过程，发现了一个教科书之外的常见现象：标准的四次挥手在无数据传输时会优化为**三次挥手**（第二、三次合并），这印证了TCP的**延迟确认（Delayed ACK）**与**捎带确认（Piggybacking）**机制。这一观察让我对TCP状态机的理解从“背诵状态图”深入到“理解设计动机”。
