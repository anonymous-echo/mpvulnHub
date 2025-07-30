#  无认证也能入侵？Commvault 现严重漏洞，黑客可借此远程 “掌控” 系统   
看雪学苑  看雪学苑   2025-04-24 09:59  
  
在当今数字化时代，数据已成为企业最为关键的资产之一，而数据保护平台的安全性直接关系到企业的核心利益与用户的隐私安全。然而，近期一则关于 Commvault Command Center Innovation Release 版本存在严重安全漏洞的消息，如同一颗突然投下的炸弹，在网络安全领域引发了广泛关注。  
  
  
该漏洞编号为 CVE-2025-34028，是一个典型的路径遍历漏洞，具有极高的危险性，其 CVSS 评分高达 9.0 分。攻击者可以借助这个漏洞上传恶意的 ZIP 文件，而当目标服务器对这些文件进行解压缩操作时，就会触发远程代码执行 （RCE），从而让攻击者得以在服务器上运行任意的恶意代码，可能导致整个系统的完全失陷。换而言之，黑客们就如同找到了一把万能钥匙，能够悄无声息地潜入系统内部，为所欲为，窃取敏感数据、篡改系统配置或是进一步传播恶意软件等。  
  
  
Commvault 作为一家在数据保护领域颇具影响力的企业，其 Command Center 是用于管理和监控数据保护操作的重要组件。此次漏洞的爆发，无疑给众多使用该版本的用户带来了巨大的风险。据相关安全研究人员分析，这个漏洞主要存在于 Commvault Command Center Innovation Release 版本 11.38 中，而其他版本则暂未受到影响。不过，由于该版本在市场中有着较为广泛的部署，所以一旦被不法分子大规模利用，后果将不堪设想。  
  
  
更令人担忧的是，这一漏洞的利用门槛极低，攻击者无需经过任何身份认证，无论身处何地，只要有网络连接，就能够向存在漏洞的目标服务器发起攻击。这无疑大大增加了被攻击的可能性，也让众多企业和机构面临着前所未有的安全挑战。  
  
  
然而，值得庆幸的是，Commvault 公司在得知此漏洞后迅速采取了行动。据公开信息显示，Commvault 在 2025 年 4 月 10 日发布了版本 11.38.20 和 11.38.25，成功修复了该漏洞。这体现了 Commvault 对产品安全问题的高度重视以及快速响应的能力。而且，Commvault 还提到其创新版本是按照预设的计划进行自动更新的，这意味着大多数用户无需手动干预，就能够及时获得更新后的安全版本，有效抵御潜在的威胁。  
  
  
不过，对于那些由于各种原因无法立即完成更新的用户，安全专家建议采取紧急措施，将 Command Center 安装实例与外部网络进行隔离，切断攻击者可能的入侵路径，以最大程度降低风险，保障系统的相对安全，直到能够顺利应用补丁为止。  
  
  
此次事件也暴露出 Commvault 产品在过去一段时间内存在的安全隐患。此前，在 2025 年年初，Commvault 产品还被发现存在其他一些严重的安全问题，比如关键的 Web 服务器漏洞（CV_2025_03_1）和 SQL 注入漏洞（CV_2025_04_2）。这些问题的接连出现，虽然在一定程度上反映出软件在复杂的应用环境中难以完全避免漏洞的产生，但也提醒了用户在选择和使用数据保护平台时，需要更加谨慎地考虑供应商的安全能力和响应机制。  
  
  
  
资讯来源：  
cybersecuritynews  
  
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
  
