#  微软修复78个漏洞，5个零日漏洞被利用，Azure惊现满分漏洞   
看雪学苑  看雪学苑   2025-05-14 09:59  
  
本周二，微软发布月度安全更新，共修复78个安全漏洞，其中包含5个已被黑客组织实际利用的"零日漏洞"，以及一个影响Azure DevOps Server的CVSS满分（10分）高危漏洞。此次修复涉及Windows系统、Office套件、Azure云平台等核心产品，再次为全球企业网络安全敲响警钟。  
  
  
据微软安全响应中心披露，本次修复的漏洞中，11个被评定为"严重"级别，66个为"重要"级别。从漏洞类型来看，28个存在远程代码执行风险，21个可能导致权限提升，16个涉及信息泄露。值得关注的是，五个已被实际利用的零日漏洞均与系统核心组件相关：  
  
  
1. CVE-2025-30397（CVSS 7.5）：脚本引擎内存损坏漏洞，攻击者可通过恶意网页触发内存错误，在用户权限下执行任意代码。Action1公司CEO指出，若用户具有管理员权限，攻击者可完全控制系统。  
  
  
2. CVE-2025-30400（CVSS 7.8）：桌面窗口管理器权限提升漏洞，这是近三年来第三个被利用的DWM组件漏洞。此前同类漏洞曾被用于传播QakBot银行木马。  
  
  
3. CVE-2025-32701/32706（CVSS 7.8）：CLFS日志系统驱动漏洞，自2022年以来该组件已出现8个被利用漏洞。上月发现的同类漏洞曾遭Play勒索软件团伙利用。  
  
  
4. CVE-2025-32709（CVSS 7.8）：WinSock网络驱动漏洞，朝鲜黑客组织Lazarus曾被指利用类似漏洞实施攻击。  
  
  
美国网络安全局（CISA）已将这五项漏洞列入"已知被利用漏洞"清单，要求联邦机构在2025年6月3日前完成修复。安全专家提醒，普通企业也应尽快部署补丁，特别是暴露在公网的服务端系统。  
  
  
此次最严重漏洞CVE-2025-29813（CVSS 10.0）存在于Azure DevOps Server，允许攻击者通过网络进行权限提升。微软表示云服务已完成修复，但本地部署用户需手动更新。这是今年首个获得满分的云计算漏洞，凸显云平台安全防护的严峻形势。  
  
  
其他重点修复包括：  
  
- Linux版Defender端点防护存在本地提权风险（CVE-2025-26684）  
  
- 企业身份防护系统存在凭证窃取隐患（CVE-2025-26685）  
  
- 新版Edge浏览器累计修复8个Chromium内核漏洞  
  
  
全球安全生态链联动响应，Adobe、思科、谷歌等50余家科技巨头同步发布补丁。专家建议企业立即启动以下措施：  
  
1. 优先修复被CISA标记的5个零日漏洞  
  
2. 检查Azure DevOps Server版本并升级至2020.1.2/2022.1.2  
  
3. 对存在Java环境的Linux设备进行权限审查  
  
4. 启用多因素认证防范凭证窃取攻击  
  
  
  
资讯来源：  
thehackernews  
  
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
  
