> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0NDcyMjU2OQ==&mid=2247484819&idx=1&sn=8cdfd3c0549e4a8395b9b6cc4ba0cca9

#  高危！MCP工具曝远程代码执行漏洞，超43万次下载受影响  
原创 DarkLuke  SecLink安全空间   2025-07-21 05:25  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/w5LtdQbOj8meb5ndQfobHXbDxp4FfkmCiamTYc6khibickDOarPicD6ic6P1fEQ6BpAPfXSGp3SKrtLzI2Eo5DobPSA/640?wx_fmt=gif&from=appmsg "")  
  
全文共计1026字，预计阅读7分钟  
## 漏洞概述  
  
网络安全研究人员近日在开源项目 **mcp-remote**  
 中发现一个**高危漏洞（CVE-2025-6514，CVSS评分9.6/10）**  
，攻击者可利用该漏洞在目标系统上执行任意操作系统命令，导致**设备完全被控制**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/w5LtdQbOj8mWiaicHCV837TB32uN6jLxVVFPxFBbwJMbo5zP17Ufhj023cXM0Gbt2h72QuicianhzQnoS3a8yXibLuQ/640?wx_fmt=png&from=appmsg "")  
  
该工具是Anthropic公司发布的**模型上下文协议（MCP）**  
的配套组件，用于连接远程MCP服务器与本地AI应用（如Claude Desktop）。据统计，其npm包下载量已超**43.7万次**  
，影响范围广泛。  
## 漏洞技术细节  
### 1. 攻击原理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/w5LtdQbOj8mWiaicHCV837TB32uN6jLxVVrnQ5HzvlmeUCOkGGO0DgtsFV6FyYcxXXt7poQmCpKCzmADOfTx2AyQ/640?wx_fmt=png&from=appmsg "")  
- **触发条件**  
：当用户使用受影响版本（0.0.5至0.1.15）的mcp-remote连接**不可信的MCP服务器**  
时，恶意服务器可在初始通信阶段嵌入恶意命令。  
  
- **执行机制**  
：mcp-remote在处理服务器响应时未对输入进行严格过滤，导致命令被直接传递给操作系统执行。  
  
- **平台差异**  
：  
  
- **Windows**  
：可完全控制命令参数，实现任意代码执行。  
  
- **macOS/Linux**  
：仅能执行有限参数的可执行文件。  
  
### 2. 关联漏洞  
- **CVE-2025-49596（CVSS 9.4）**  
：MCP Inspector工具的Web UI默认无认证，攻击者可通过"邻居劫持"（NeighborJacking）或恶意网页注入代码，实现远程攻击。  
  
- **文件系统MCP服务器漏洞**  
：  
  
- **CVE-2025-53110（7.3分）**  
：目录穿越漏洞，可访问系统任意文件（如
```
/etc/sudoers
```

  
）。  
  
- **CVE-2025-53109（8.4分）**  
：符号链接绕过漏洞，通过错误处理机制篡改关键文件。  
  
## 影响范围  
- **受影响版本**  
：mcp-remote 0.0.5至0.1.15。  
  
- **风险场景**  
：  
  
- 连接第三方或未加密（非HTTPS）的MCP服务器。  
  
- 在共享网络环境中运行MCP工具（如企业内网）。  
  
## 修复方案  
  
1.**立即升级**  
：更新至mcp-remote **0.1.16**  
（2025年6月17日发布）。  
  
2.**访问控制**  
：仅连接可信MCP服务器，并强制使用**HTTPS加密**  
。  
  
3.**网络隔离**  
：在沙箱或隔离环境中运行MCP相关服务。  
> ❝  
> **专家警告**  
： "MCP协议正成为AI应用的'通用接口'，但若忽视基础安全实践，此类漏洞将导致灾难性后果。" ——安全研究员Rémy Marot  
  
## 漏洞背景  
  
MCP协议旨在标准化AI应用与外部数据源的交互，但其生态工具频曝漏洞：  
- **2025年7月初**  
：Anthropic文件系统MCP服务器曝出沙箱逃逸漏洞（CVE-2025-53109/53110）。  
  
- **历史问题**  
：MCP客户端与恶意服务器交互的风险此前已被研究，但本次是首次实现**真实场景下的RCE**  
。  
  
## 防御建议  
- **企业用户**  
：部署网络流量监控，拦截异常MCP连接请求。  
  
- **开发者**  
：在代码中显式校验服务器响应，避免直接调用系统命令。  
  
**注**  
：本文技术细节已简化，完整报告可参考JFrog安全公告。  
  
  
  
  
请关注**SecLink安全空间**  
获取我们最新的更新  
  
  
  
欢迎加入**SecLink安全空间**  
微信群  
探讨安全问题！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/w5LtdQbOj8lWZiaxTq4Y8spYawkEdXhwsXR6n5Y5ok1dsxvZb25oY38UAD9V0jMMJJnOiaVqz2p19U8V4Goib9u4Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
