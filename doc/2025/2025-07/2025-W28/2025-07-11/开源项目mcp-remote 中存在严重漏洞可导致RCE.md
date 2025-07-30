> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523555&idx=2&sn=04a84283c9d2100a95736c652525dcd8

#  开源项目mcp-remote 中存在严重漏洞可导致RCE  
Ravie Lakshmanan  代码卫士   2025-07-11 10:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全研究员在开源项目 mcp-remote 中发现了一个严重漏洞CVE-2025-6514，CVSS评分9.6，可导致执行任意操作系统命令后果。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRibSOf2oefmWuft2DriawV8ic11jXPybxL40XUtBdk0dGDibBK91vDyj2lfFgwRpHXvcLpahgCyMdhzg/640?wx_fmt=png&from=appmsg "")  
  
  
JFrog 公司的漏洞研究团队负责人 Or Peles 表示，“当机器初始化对不受信任的 MCP 服务器的连接时，该漏洞可导致攻击者在运行 mcp-remote 的机器上触发任意OS命令执行，从而对用户造成严重风险即完全攻陷系统。”  
  
Mcp-remote 是在 Anthropic 公司发布旨在标准化大语言模型应用集成和与外部数据来源和服务共享数据方式的开源框架模型上下文协议 (MCP)后，推出的一款工具。该工具作为本地代理，可使MCP客户端如 Claude Desktop 与远程MCP服务器进行通信，而不是与 LLM 应用一样在同一台机器上本地运行。迄今为止，该开源工具的 nmp 包的下载次数已经超过43.7万次。  
  
该漏洞影响 mcp-remote 0.05至0.1.15版本，已在2025年6月17日发布的0.1.16版本中修复。任何使用 mcp-remote 连接到不可信或使用受影响版本的不安全MCP服务器的用户，均受影响。  
  
Peles 表示，“之前发布的研究已展现了MCP客户端连接到恶意 MCP 服务器带来风险，而这是首次在真实世界中，客户端操作系统连接到不可信远程MCP服务器后，实现完全远程代码执行。”  
  
该漏洞与恶意MCP服务器将命令嵌入初始通信建立与授权阶段之间有关，当mcp-remote处理该命令时，就会导致它在底层操作系统上被执行。该漏洞导致以完整参数控制在Windows系统上执行任意OS命令，造成在 macOS 和 Linux 系统上具有有限参数的任意可执行文件的执行。  
  
要缓解这一风险，建议用户将库更新至最新版本并通过HTTPS仅连接至可信的MCP服务器上。Peles 表示，“虽然远程MCP服务器能够高效地在管理环境中扩展AI能力、便于快速迭代代码并助力确保交付更可靠的软件，但MCP用户应当注意仅使用安全连接方法如HTTPS连接到可信 MCP 服务器。否则，CVE-2025-6514类的漏洞很可能会劫持不断扩大的 MCP 生态系统中的MCP客户端。”  
  
此前不久，Oligo Security 公司详述了 MCP Inspector 工具中的一个严重漏洞（CVE-2025-49596，CVSS评分9.4），可用于实现远程代码执行后果。  
  
本月早些时候，Anthropic 公司的 Filesystem MCP Server 中被指存在两个高危漏洞，如遭成功利用，可导致攻击者突破该服务器的沙箱、操纵主机上的任意文件并实现代码执行。这两个漏洞如下：  
  
- CVE-2025-53110（CVSS评分7.3）：该目录隔离绕过漏洞可允许攻击者使用在其它目录（如 “/private/tmp/allow_dir_sensitive_credentials”）上的目录前缀，访问、读取或写入超出授权目录范围（如 “/private/tmp/allowed_dir”）的目录，从而可导致数据被盗和提权后果。  
  
- CVE-2025-53109（CVSS评分8.4）：符号链接绕过漏洞，源自错误处理不当。攻击者可从授权目录中利用此方式指向文件系统中的任意文件，从而读取或修改关键文件（如 “/etc/sudoers”）或释放恶意代码。利用 Lauch Agents、cron 任务或其它持久化技术，可能导致代码执行后果。  
  
  
  
这两个漏洞影响所有早于 0.6.3和2025.7.1的 Filesystem MCP Server 版本。安全研究员 Elad Beber 在谈到 CVE-2025-53110时表示，“该漏洞是对 Filesystem MCP Servers安全模型的严重违反。攻击者能够通过列表、读取或写入可允许范围之外目录的方式，获得越权访问权限，从而暴露敏感文件如凭据或配置。更糟糕的是，在服务器以权限用户运行的设置中，该漏洞可导致提权，从而允许攻击者操纵关键系统文件并获得对主机系统更深层的控制。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软 Edge 修复两个高危RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523450&idx=1&sn=fb41027f31142b3eef6b9494edc4b71e&scene=21#wechat_redirect)  
  
  
[速修复！Grafana 修复中存在四个严重的RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523440&idx=2&sn=85a84a9138ea24b09e9ea0bcb9efe061&scene=21#wechat_redirect)  
  
  
[Sitcore XP中的硬编码密码 “b” 导致企业系统易受RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523347&idx=2&sn=b6f02b127ba49b7fa05eec183cb4108a&scene=21#wechat_redirect)  
  
  
[《2025中国软件供应链安全报告》发布：大模型、智能网联车风险亟待重视](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523515&idx=1&sn=0b90d847c5fba9db87395a652595fafc&scene=21#wechat_redirect)  
  
  
[大语言模型加速供应链攻击，只是时间问题](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521932&idx=2&sn=ca363bafcb541f84bed911b9db4e071d&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/07/critical-mcp-remote-vulnerability.html  
  
  
题图：  
Pixabay Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
