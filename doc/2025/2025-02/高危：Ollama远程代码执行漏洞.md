#  高危：Ollama远程代码执行漏洞   
原创 吉祥  吉祥快学网络安全吧   2025-02-22 04:28  
  
近期，开源AI模型部署工具Ollama曝出高危远程代码执行漏洞（CVE-2024-37032），CVSS评分高达9.1，**攻击者无需身份验证即可通过接口操控服务器，实现任意代码执行**  
。这一漏洞已在全球范围内影响近6000台暴露在公网的Ollama服务器。本文将深入解析漏洞原理、危害及修复方案，并附技术复现细节。  
#### 漏洞概述  
  
**漏洞编号**：CVE-2024-37032（关联QVD-2024-21275）**影响版本**：Ollama < 0.1.34**风险等级**：高危（CVSS 3.1 9.1）**利用条件**：未启用身份验证的Ollama服务（默认监听11434端口）。  
  
Ollama作为热门的AI模型部署工具，允许用户快速启动Llama等大模型。然而，其早期版本因接口设计缺陷，导致攻击者可**通过路径穿越写入恶意文件，最终控制服务器**。  
##### 漏洞根源  
  
在Ollama的server/modelpath.go代码中，digest参数未对用户输入进行有效过滤，攻击者通过/api/pull或/api/push接口提交包含路径穿越符（如../../）的请求，将恶意文件写入系统关键路径（如/etc/ld.so.preload），触发动态库劫持，实现**远程代码执行（RCE）**。  
##### 核心危害  
1. **服务器完全控制**：攻击者可植入后门、窃取模型数据或部署勒索软件。  
  
1. **模型投毒与窃取**：篡改或窃取AI模型，导致业务逻辑破坏或知识产权泄露。  
  
1. **供应链攻击**：若Ollama作为企业AI服务的基础组件，漏洞可能横向扩散至内部系统。  
  
#### 漏洞复现（POC）  
  
以下为模拟攻击的核心步骤（仅供技术研究）：  
1. **构造恶意模型请求**：```
# 通过/api/pull接口拉取恶意模型
curl -X POST http://<target-ip>:11434/api/pull -d '{  "name": "malicious_model",  "digest": "../../etc/ld.so.preload"}'

```  
  
  
1. **写入恶意动态库路径**：攻击者将恶意库路径写入/etc/ld.so.preload，系统加载时自动执行恶意代码。  
  
1. **触发代码执行**：重启Ollama服务或等待系统进程调用动态库，攻击载荷（如反弹Shell）即被激活。  
  
#### 修复建议  
1. **升级至安全版本**：官方已在0.1.34版本修复漏洞，**立即升级**至Ollama ≥0.1.34。  
```
# 通过GitHub获取最新版本
https://github.com/ollama/ollama/releases

```  
  
  
1. **启用身份验证**：为Ollama服务配置强制认证（如API密钥或OAuth），避免未授权访问。  
  
1. **网络隔离与访问控制**：  
  
1. 限制Ollama服务的公网暴露，仅在内网开放必要端口。  
  
1. 通过防火墙或WAF过滤/api/pull和/api/push接口的异常请求。  
  
CVE-2024-37032的公开EXP和广泛影响使其成为2024年AI领域最危险的漏洞之一。**未修复的服务器相当于将Docker套接字暴露在公网**，攻击者可长驱直入。企业需立即行动，结合升级、隔离、监控三管齐下，筑牢AI基础设施的安全防线。  
## 星球介绍  
  
一个人走的很快，但一群人才能地的更远。吉祥同学学安全这个[星球🔗](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247486065&idx=2&sn=b30ade8200e842743339d428f414475e&chksm=c0e4732df793fa3bf39a6eab17cc0ed0fca5f0e4c979ce64bd112762def9ee7cf0112a7e76af&scene=21#wechat_redirect)  
成立了1年左右，已经有300+的小伙伴了，如果你是网络安全的学生、想转行网络安全行业、需要网安相关的方案、ppt，戳[链接🔗（内有优惠卷）](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247485310&idx=1&sn=616e51776b8c4c15e23eccd9a14762d3&chksm=c0e47e22f793f7340ff4cfb3820968296076f55f1a52938ae9fe04a52883a3be3a4e818d2e96&scene=21#wechat_redirect)  
快加入我们吧。系统性的知识库已经有：[《Java代码审计》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484219&idx=1&sn=73564e316a4c9794019f15dd6b3ba9f6&chksm=c0e47a67f793f371e9f6a4fbc06e7929cb1480b7320fae34c32563307df3a28aca49d1a4addd&scene=21#wechat_redirect)  
++[《Web安全》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484238&idx=1&sn=ca66551c31e37b8d726f151265fc9211&chksm=c0e47a12f793f3049fefde6e9ebe9ec4e2c7626b8594511bd314783719c216bd9929962a71e6&scene=21#wechat_redirect)  
++[《应急响应》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484262&idx=1&sn=8500d284ffa923638199071032877536&chksm=c0e47a3af793f32c1c20dcb55c28942b59cbae12ce7169c63d6229d66238fb39a8094a2c13a1&scene=21#wechat_redirect)  
++[《护网资料库》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484307&idx=1&sn=9e8e24e703e877301d43fcef94e36d0e&chksm=c0e47acff793f3d9a868af859fae561999930ebbe01fcea8a1a5eb99fe84d54655c4e661be53&scene=21#wechat_redirect)  
++[《网安面试指南》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247486695&idx=1&sn=85fefa98f17e6f1f2dd745ef5a498a10&token=1860256701&lang=zh_CN&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Oh2kiaia4icySA7oIU4p2qDG8uXicgOGAwz8rniaSc1ryMag9CMdJGaQ0rSpVYh1pS1apJP2aicBcz88vOm0JysoQLww/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
