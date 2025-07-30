> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIyMzIwNzAxMQ==&mid=2649468656&idx=1&sn=dc7a79aeaca6e4002a6fbc1d6ff6c0ea

#  端口映射 ≠ 内网穿透 ≠ NAT！99%的人都搞混了！建议收藏！  
原创 wljslmz瑞哥  网络技术联盟站   2025-06-13 07:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/6OibpDQ66VYQNIyABHZrCWcZT6asQr23iaO5wvXibL4CtruQ1E2AY6iaaH3X4LxMnSrBXvjhQND7Y4ibRahz9FhPVBw/640?wx_fmt=gif "")  
  
> 公众号：网络技术联盟站   
  
  
  
互联网那么大，为什么我家里的设备连不上外面的世界？  
  
NAT？端口映射？内网穿透？这三个到底是一个意思，还是完全不同？  
  
别急，今天这篇文章，带你一次性彻底搞懂这几个**网络世界的“玄学”名词**  
。建议点赞收藏 📌，早晚用得上！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/6OibpDQ66VYRTGj40ibNefRRkJQeBYzpzialFZ7gw4WMCFpUNI2Mianp4UHSw7XGA5Ot482YiaicKIk1fpD69JnCzn3A/640?wx_fmt=jpeg&from=appmsg "")  
## 📌 为什么会有这几个概念？  
  
在互联网早期，**IPv4地址**  
足够用，**每台设备都能有一个公网IP**  
，直接就能访问彼此。  
  
但 **IPv4地址耗尽**  
 后，ISP（互联网服务提供商）开始大规模部署 **私有地址（内网IP） + NAT技术**  
。  
  
结果就出现了——  
1. **设备在内网中互联没问题**  
  
1. **设备访问公网也没问题**  
  
1. **但公网设备反过来访问内网设备——难了！**  
  
于是，**端口映射**  
 和 **内网穿透**  
 这些“拯救世界”的方案就被开发出来……  
## 🚀 核心概念  
### 1️⃣ NAT  
- Network Address Translation，网络地址转换  
  
**✔ 本质：**  
  
NAT 是一种**网络地址转换技术**  
，它**将私有地址转换为公网地址**  
，或者反过来。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6OibpDQ66VYRTGj40ibNefRRkJQeBYzpzia6RlbTsvuicbux8tLXH7iaZicDycYNGhe8HibT9XjXzNyxzQgshNds0ToAg/640?wx_fmt=png&from=appmsg "")  
#### 📖 分类：  
  
**SNAT（源地址转换）**  
：  
- 内网 → 公网  
  
- 多个内网设备“伪装成”同一个公网IP访问互联网  
  
- **DNAT（目的地址转换）**  
：  
  
- 公网 → 内网  
  
- 通过端口映射实现，将“公网IP+端口号”映射到**内网指定设备**  
  
#### 📌 作用：  
- **节省公网IP**  
  
- **隐藏内部网络结构**  
  
- **一定程度上的安全保护**  
  
#### 🎯 举个例子：  
> 你家有个192.168.1.100的摄像头，ISP分配的公网IP是**101.1.2.3**  
。当你在外网输入
```
http://101.1.2.3:5000
```

**——> NAT（DNAT）就会把这个请求“翻译”到你家摄像头的5000端口。**  
  
### 2️⃣ 端口映射  
- Port Mapping / Port Forwarding  
  
**✔ 本质：**  
  
**端口映射其实是DNAT的一种应用场景**  
，通过NAT设备（一般是路由器）设置，将**公网某个端口映射到内网某个设备对应端口**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6OibpDQ66VYRTGj40ibNefRRkJQeBYzpziaaVzK2UEQDNhblkrrjnmrJeADIjLfuvZfaGEicc7NcDanD5HmicJMicKGQ/640?wx_fmt=png&from=appmsg "")  
#### 📖 分类：  
- **静态端口映射**  
：固定端口  
  
- **动态端口映射（UPnP）**  
：设备动态申请  
  
#### 📌 作用：  
- **让外部用户访问内网设备**  
  
典型场景：  
- 内网搭建Web服务  
  
- NAS远程访问  
  
- 游戏服务器  
  
- 远程桌面  
  
#### 🎯 举个例子：  
> **外部访问：**  
 
```
http://101.1.2.3:8080
```

**内部实际：**  
 
```
http://192.168.1.50:80
```

**→ 路由器做了端口映射（公网8080 -> 内网80）**  
  
#### ⚠️ 局限性：  
- **公网IP受限**  
  
- **配置繁琐**  
  
- **部分运营商做“二级NAT”，端口映射根本不起作用！**  
  
### 3️⃣ 内网穿透  
- NAT Traversal  
  
**✔ 本质：**  
  
**内网穿透是绕过NAT限制，主动打洞，让内网设备能被公网访问**  
的一种技术。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6OibpDQ66VYRTGj40ibNefRRkJQeBYzpziayia4m4ibvnwuYXP96uluedQwwQFjt5qiatLyZWuY4TQWeVtq9OQia48Ulg/640?wx_fmt=png&from=appmsg "")  
> ⚠️ **它不是NAT功能，是“绕开NAT”的技术手段！**  
  
#### 📖 实现方式：  
- **P2P打洞（STUN、TURN、ICE）**  
：多用于视频会议、VoIP  
  
**中继服务器转发（反向代理）：  
- Ngrok  
  
- Frp  
  
- 花生壳  
  
- ZeroTier  
  
- tailscale  
  
**公网服务器反向连接**  
：  
- 客户端 → 公网服务器 → 用户 → 内网设备  
  
#### 📌 作用：  
- **突破多层NAT限制**  
  
- **无需公网IP**  
  
- **动态自动穿透，适合复杂网络**  
  
#### 🎯 举个例子：  
> 你家里搭了个NAS，没有公网IP，端口映射根本不管用。**用 Frp 或 Ngrok 建立穿透 → 外部访问“abc.ngrok.io:8888” → 就能访问你家NAS了。**  
  
#### ⚠️ 局限性：  
- **对带宽性能有影响（尤其是走中继服务器时）**  
  
- **部分穿透方式存在安全风险**  
  
- **稳定性依赖第三方服务**  
  
## ⚡ 三者的对比：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6OibpDQ66VYRTGj40ibNefRRkJQeBYzpzias9gmwm4rWrC5aGN0GRe7FSA8qbzKbiaKZya7dfvv360ryW7aOWwVboQ/640?wx_fmt=png&from=appmsg "")  
## 💡 四、为什么很多人会搞混？  
  
原因很简单：  
1. **端口映射用的是 NAT**  
 → NAT 和端口映射傻傻分不清  
  
1. **内网穿透也是为了“让内网设备被外部访问”**  
 → 很多人觉得和端口映射是“一回事”  
  
1. **NAT术语过于抽象**  
 → 大部分用户接触的是“端口映射”界面，不知道其实背后是 NAT 技术  
  
## 📂 常见场景对应方案  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6OibpDQ66VYRTGj40ibNefRRkJQeBYzpzia9PyKylX8Tc2lmfSIKeYian6EwGo0wWbsth1XTRQYp6VibiaTfAvALZAiag/640?wx_fmt=png&from=appmsg "")  
## ⚠️ 安全性必须重视  
  
**注意：开放内网服务 ≠ 安全！**  
  
使用端口映射时：  
- 强烈建议 **使用非默认端口**  
  
- 配置防火墙  
  
- 添加访问控制列表（ACL）  
  
使用内网穿透时：  
- 优先选择 **加密传输**  
  
- 使用自建穿透服务代替第三方  
  
- 尽量配置白名单访问  
  
## 🎯 IPv6 能解决这些烦恼吗？  
  
**答案：部分能，但不会完全替代。**  
- **IPv6**  
天然具备全球唯一地址 → 没有 NAT → 每台设备理论上都可以“直接访问”  
  
但是！  
- **安全性问题**  
，公网暴露风险增大  
  
- **运营商 IPv6 部署不完整**  
  
- 终端设备 IPv6 配置复杂  
  
- 很多旧设备、软件 **不支持 IPv6**  
  
> **IPv6 是未来趋势，但目前 IPv4 + NAT + 穿透 依然是主流。**  
  
## 🏆 总结一句话  
  
**NAT 是“翻译官”，端口映射是“指定路线”，内网穿透是“钻地道”**  
。  
  
**✅ 三者本质不同，但目标一致：让内网和公网之间建立联系。**  
  
如果你还没彻底搞懂？  
  
建议——**收藏 + 转发 + 再读一遍 🔁**  
  
**关注“网络技术联盟站”，带你解锁更多“网络黑科技”！**  
  
  
  
  
**喜欢就**  
**分享**  
  
**认同就**  
**点赞**  
  
**支持就**  
**在看**  
  
**一键四连，你的技术也四连**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/6OibpDQ66VYRJ20XxicqZhK1qicQFqicZN3BDMEIvovHPnsWicnRgkibCNOtcZf7icVkErP0b18JZia29GVKLkhR5IJ1ibQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
