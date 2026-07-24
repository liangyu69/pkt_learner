# PKT_Learner
A packet capture tool for learning computer network principles
## compile

```bash
make

## 📡 项目亮点

在学习TCP协议时，我使用本工具抓包验证了连接释放过程，发现了一个教科书之外的常见现象：标准的四次挥手在无数据传输时会优化为**三次挥手**（第二、三次合并），这印证了TCP的**延迟确认（Delayed ACK）**与**捎带确认（Piggybacking）**机制。这一观察让我对TCP状态机的理解从“背诵状态图”深入到“理解设计动机”。