#  Fortinet 漏洞再现，攻击者利用新方法入侵   
看雪学苑  看雪学苑   2025-04-14 10:02  
  
近期，网络安全领域风波不断，Fortinet 防火墙漏洞问题再次引发广泛关注。据相关报道，Fortinet 承认攻击者已找到新方法，利用其认为已在去年修复的三个漏洞。这些漏洞涉及 FortiGate 和 FortiOS 设备，攻击者通过创建符号链接（symlinks），将用户链接到根文件系统，从而获得只读权限，访问包括系统配置文件在内的资源。Fortinet 已采取措施缓解该问题，并通知受影响客户，建议无法及时更新系统的用户禁用 SSL-VPN。  
  
  
此外，Fortinet 的 FortiOS 和 FortiProxy 产品还存在身份认证绕过漏洞（CVE-2024-55591），该漏洞自 2024 年 11 月起已被攻击者利用。攻击者通过向 Node.js websocket 模块发送特制请求，可获取超级管理员权限，进而创建非法管理员账户、修改防火墙策略，并通过 SSL VPN 访问内部网络。该漏洞影响多个版本，包括 FortiOS 7.0.0 至 7.0.16、FortiProxy 7.0.0 至 7.0.19 和 7.2.0 至 7.2.12。Fortinet 已在 2025 年 1 月发布安全更新，修复了该漏洞，建议受影响用户尽快升级到安全版本。  
  
  
在另一项研究中，研究人员发现中国生产的机器人狗（Unitree Go1）被发现在美国销售时，预装了连接到中国远程访问平台的隧道客户端。一旦研究人员获取了相关 API 的访问权限，他们就可以完全控制这些机器人狗，包括通过其视觉摄像头查看图像，甚至通过 SSH 连接到 RPI。研究人员建议立即将这些机器人从网络中隔离，并检查日志以查找可疑流量。  
  
  
同时，美国国家标准化与技术研究院（NIST）因处理漏洞提交积压问题，宣布将 2018 年 1 月 1 日之前发布的大量 CVE 标记为“延迟”状态。这意味着，除非绝对必要，否则这些旧 CVE 将不再获得更新。  
  
  
荷兰政府也遭遇了数据泄露事件，多个政府部委卷入其中，但具体细节尚不清楚。荷兰经济事务和气候及绿色增长部已确认受到影响，且可能还有其他部门也受到波及。目前，荷兰数据保护局已被告知此事。  
  
  
  
资讯来源：  
hackread  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
