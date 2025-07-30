> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247486111&idx=1&sn=b7d8865b37ec95f6ad4484cd959fc3ea

#  Docker API 漏洞成黑客跳板，配合Tor 匿名网络正偷走你的加密货币  
龙猫  星尘安全   2025-06-25 02:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/qTcIBaTRMWdjcGWCVUAKtpd05lBUJo0eJ4bg9ujlbhoFeMUcSBFia6tzfs0GPK3RRcLC8vysusEFvqicJ0VGicMtA/640?wx_fmt=png "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibV6vqVQpnKD9eLpCQAf69UFrxu8NdzsuFfBDKuKia0X9xJm2mFicP6xnfvpUSafPWB448zx1apYe9Tt76TgsJ12Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JmssGpneVHK2aNAIsS7yQ1icFsQMnHqJhsY5gGWBhGwlDF4mVgbdT6WG0ialZ1GdFOYblVeBCAQzTQhYbBFS7Wog/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vSWrxetgNEwFYKj5BheiaG6kNBOq6qQrIz9AU85ichuianaFNzFE5xqPMcjcfj5yjQN7em46j9R8Z0A/640?wx_fmt=png&from=appmsg "")  
  
近期，趋势科技披露了一起针对云容器环境的新型攻击活动。攻击者通过扫描暴露在公网的**Docker 远程 API 接口**  
（Docker Remote API），利用配置缺陷获取容器管理权限。具体攻击流程如下：  
  
  
**初始入侵**  
  
通过 IP 地址 198.199.72.27 向目标服务器发送容器列表查询请求，确认可攻击目标。  
  
**权限提升**  
  
基于 "alpine" 基础镜像创建新容器，通过挂载主机根目录（/:/hostroot:rw）突破容器隔离边界，实现对宿主机的访问控制。  
  
**匿名化部署**  
  
在容器内搭建 Tor 节点，通过 ".onion" 隐藏服务地址下载恶意脚本 "docker-init.sh"，并利用socks5h协议实现流量与 DNS 解析的全链路匿名化。  
  
**挖矿程序植入**  
  
最终部署 XMRig 加密货币挖矿程序，结合 zstd 压缩技术优化传输效率，确保恶意组件在内存中高效运行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HicKxOBuNb9wSMkRqYMNdZIpf6Bdu4TjXucibWGvdQgjp7w8nxIkvqHeDblk3rD0oCAkEhDEXWQibKYK7Ubzqdq1A/640 "")  
  
  
**01**  
  
**攻击目标特征与行业影响**  
  
该攻击呈现显著的行业靶向性，主要针对**云原生技术密集型领域**  
，包括科技、金融服务和医疗行业。趋势科技指出，暴露的 Docker API 已成为云安全的高频攻击面 —— 此前名为 "Commando Cat" 的攻击团伙已多次利用同类漏洞实施加密劫持（Cryptojacking）。尽管本次攻击是否与该团伙相关尚未确认，但数据显示，**全球约 37% 的 Docker 环境存在 API 未授权访问风险**  
（来源：Trend Micro 2025 云安全报告）。  
  
值得警惕的是，容器化技术的普及使得攻击面进一步扩大。无论企业规模大小，**任何未遵循最小权限原则配置的 Docker 环境均可能成为目标**  
。攻击者通过 Tor 网络的多层匿名机制，将传统基于 IP 信誉的检测手段有效规避，导致攻击行为在云日志中呈现低可观测性特征。  
  
**02**  
  
**防御体系构建：基于容器生命周期的安全策略**  
  
针对此类攻击，企业需建立覆盖**配置管理、运行时监控、应急响应**  
的全流程防护体系：  
### （一）基础设施层安全加固  
1. **API 访问控制**  
1. 禁用公网对 Docker API 的直接访问，通过 VPN 或内部负载均衡器限制仅授权 IP 访问  
  
1. 启用 TLS 双向认证（mTLS），对 API 请求进行签名验证  
  
1. **容器配置最佳实践**  
1. 采用非 root 用户运行容器（
```
USER app:app
```

  
），通过
```
seccomp
```

  
和
```
apparmor
```

  
限制系统调用  
  
1. 使用 Docker Content Trust 确保镜像来源可信，禁止拉取未经验证的第三方镜像  
  
### （二）运行时威胁检测  
1. **异常行为分析**  
1. 部署容器安全平台（如 Aqua Security、Trivy），实时监控容器内进程树，识别 Tor 节点启动、异常网络连接（如.onion 域名解析）等可疑活动  
  
1. 建立基线模型，对 CPU / 内存利用率突变、异常文件写入（如 /miner 目录创建）触发告警  
  
1. **流量深度检测**  
1. 在云网关层配置 Tor 流量阻断策略，通过 DPI 技术识别加密流量中的 Tor 协议特征  
  
1. 对容器网络实施微分段（Micro-Segmentation），限制跨容器组的非法通信  
  
### （三）应急响应与持续改进  
1. **事件处置流程**  
1. 制定《容器环境感染应急预案》，明确隔离受感染容器、镜像哈希溯源、日志留存取证等操作步骤  
  
1. 定期进行红蓝对抗演练，模拟 Docker API 被入侵场景，验证防御体系有效性  
  
1. **合规性审计**  
1. 每月执行容器配置合规性扫描，对照 CIS Docker Benchmark 检查权限配置、日志审计等项目  
  
1. 建立漏洞管理闭环，通过自动化工具同步更新 Docker 引擎及依赖组件  
  
**03**  
  
**启示：从被动防御到主动免疫的范式转变**  
  
此次攻击再次凸显了云原生安全的特殊性 — **容器技术的动态性与传统安全防护的静态策略之间存在天然矛盾**  
。企业需从以下维度升级安全能力：  
- **左移安全验证**  
将安全检查嵌入 CI/CD 流水线，在镜像构建阶段完成漏洞扫描与合规性验证  
  
- **零信任架构落地**  
对容器环境实施 "永不信任，始终验证" 原则，通过 SPIFFE/SPIRE 实现容器身份动态管理  
  
- **威胁情报共享**  
接入云安全联盟（CSA）等行业组织的威胁情报网络，实时同步 Docker API 攻击 IP 列表  
  
**04**  
  
**结语**  
  
随着容器化与云原生技术的深入应用，针对 Docker 等容器平台的攻击将呈现专业化、隐蔽化趋势。企业需打破 "重功能部署、轻安全配置" 的惯性思维，将容器安全纳入整体云战略的核心范畴。通过技术工具、管理流程与人员能力的协同提升，构建具备弹性防御能力的云原生安全体系，才能有效抵御此类 "静默吸血" 式的新型攻击。  
  
[被谷歌 320 亿美金收购的云安全巨头 Wiz，到底什么来头？](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485859&idx=1&sn=2186e15f7c4ea29f5843d5cfd4ded046&scene=21#wechat_redirect)  
  
  
2025-03-21  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485859&idx=1&sn=2186e15f7c4ea29f5843d5cfd4ded046&scene=21#wechat_redirect)  
  
  
[别让数据裸奔！云应用服务器安全防护最佳实践](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485823&idx=1&sn=0f836ce8e58c7b9264497424ac0bb2ce&scene=21#wechat_redirect)  
  
  
2025-03-15  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485823&idx=1&sn=0f836ce8e58c7b9264497424ac0bb2ce&scene=21#wechat_redirect)  
  
  
[2025年，我们应当如何保护云安全？](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485476&idx=1&sn=c22f13f338cc253e4e31b0b59753d950&scene=21#wechat_redirect)  
  
  
2025-01-12  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485476&idx=1&sn=c22f13f338cc253e4e31b0b59753d950&scene=21#wechat_redirect)  
  
  
[这两年很火的云原生安全，到底在做什么？](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247483934&idx=1&sn=56967cf03a4a37d5a974dbb00bd60889&scene=21#wechat_redirect)  
  
  
2023-12-04  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247483934&idx=1&sn=56967cf03a4a37d5a974dbb00bd60889&scene=21#wechat_redirect)  
  
  
**喜欢此文的话，可以点赞、转发、在看 一键三连哦！**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vglcuxSMkmalibicmpOSAop2ebtW81WD17lIoywzweqOrtD2C7MiaU003Cdo8F8ZpWTqvY50VeDja9w/640?wx_fmt=png&from=appmsg "")  
  
  
  
