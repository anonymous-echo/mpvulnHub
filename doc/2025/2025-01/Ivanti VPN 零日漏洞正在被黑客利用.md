#  Ivanti VPN 零日漏洞正在被黑客利用   
跳舞的花栗鼠  FreeBuf   2025-01-09 11:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
Ivanti 公开披露了影响 Connect Secure (ICS) VPN 设备的两个关键漏洞：CVE-2025-0282 和 CVE-2025-0283。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39NgiakXn2PxjnbFAK7W4vosOfdgZada8CIhZo4VMMNvCba917ZUZR2z5QhTdoEYfoHLX3DfCgNKWQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
网络安全公司 Mandiant 的报告称，CVE-2025-0282 零日漏洞利用活动开始于 2024 年 12 月中旬。这一漏洞的利用引发了人们对潜在网络漏洞以及受影响组织后续损害的担忧。  
  
  
比较而言，CVE-2025-0282 是两个漏洞中更为严重的一个，被描述为未经身份验证的基于栈的缓冲区溢出漏洞。  
  
  
利用该漏洞，攻击者无需身份验证即可实现远程代码执行，从而为他们在受感染的网络中部署恶意软件或进行进一步攻击提供立足点。  
  
  
CVE-2025-0283 的信息尚未完全披露，但同样被认为是关键漏洞。  
  
  
Mandiant 的持续调查表明，CVE-2025-0282 正在被利用于针对多个组织的定向攻击活动中。  
  
  
攻击者在发起攻击前展示了探测 ICS 设备版本的高超技术，特别是针对特定软件版本中的漏洞进行攻击。  
  
  
Mandiant 观察到威胁行为者利用了一系列恶意软件家族，包括已知的 SPAWN 生态系统（SPAWNANT 安装程序、 SPAWNMOLE 隧道工具和 SPAWNSNAIL SSH 后门）。  
  
  
在受感染的设备中还识别出了两个新的恶意软件家族：DRYHOOK 和 PHASEJAM。  
  
  
**攻击技术和持久化方法**  
  
  
## 攻击者在利用 CVE-2025-0282 时典型的攻击步骤包括禁用 SELinux 等安全功能、写入恶意脚本、部署 Web Shell 以及篡改系统日志以隐藏入侵痕迹。  
  
  
特别令人担忧的是，攻击者植入了在系统升级后仍然能够存活的持久化恶意软件组件，确保即使系统被修补，攻击者仍能保持访问权限。  
  
  
分析还揭示了攻击者在 ICS 软件组件中部署了 Web Shell，以实现远程访问和代码执行。  
  
  
例如，PHASEJAM 恶意软件会劫持系统升级过程，利用基于 HTML 的虚假升级进度条，从视觉上让管理员误以为升级正在进行。实际上，恶意行为者会悄悄阻止合法升级，确保系统仍然受到入侵威胁，同时保持攻击不被发现。  
  
  
另一种恶意软件 SPAWNANT 则通过将自身嵌入系统文件来确保升级过程中的持久性。  
  
  
在漏洞利用后，还观察到威胁行为者从设备的多个关键区域删除了入侵证据：  
- 使用 dmesg 清除内核消息，并从调试日志中删除漏洞利用期间生成的条目  
  
- 删除故障排除信息包（状态转储）以及进程崩溃生成的任何核心转储  
  
- 删除与系统日志故障、内部 ICT 故障、崩溃痕迹和证书处理错误相关的应用程序事件日志条目  
  
- 从 SELinux 审计日志中删除已执行的命令  
  
##   
  
**幕后黑手是谁？**  
  
  
## Ivanti 和 Mandiant 认为此次攻击活动带有间谍活动的痕迹。  
  
  
受感染的 ICS 设备数据库缓存已多次被泄露，这引发了人们对暴露的 VPN 会话数据、 API 密钥、凭证和证书的担忧。  
  
  
网络安全专家警告称，如果这些漏洞的概念验证利用代码被公开，可能会吸引更多威胁行为者参与，从而导致攻击的范围扩大。  
  
  
Ivanti 正在处理零日漏洞 CVE-2025-0282 和 CVE-2025-0283，这两个漏洞影响了 Ivanti Connect Secure 、Policy Secure 以及 Neurons for ZTA 网关。  
修复程序可以通过下载门户获取。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
