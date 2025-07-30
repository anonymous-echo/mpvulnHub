#  年度加密漏洞提前锁定：Java JDK 加密实现漏洞可用于伪造凭据   
John Leyden  代码卫士   2022-04-21 18:46  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
Java JDK 的某些加密操作实现中存在一个灾难性漏洞，可使攻击者轻易伪造虚假凭据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTI1vbIyhibj6ueeI19w1Mj19icukwxFGP7qsadIK8ic077BpgopQMOgzdDAJMiaspXARF99rjVwSicabg/640?wx_fmt=png "")  
  
  
  
该灾难性弱点影响 Java JDK 15及后续版本，已由 Oracle 在今天的关键补丁更新发布中修复。由于这些缺陷牵涉对使用广泛的 ECDSA 签名的实现，因此 Oracle Java 和 OpenJDK 均需更新。问题源自编程错误，而非底层加密技术出现问题。  
  
如不修复，缺陷可导致攻击者伪造某些SSL 证书类型和握手，从而导致中间操纵人攻击。安全研究员 Neil Madden 提醒称，如不修复该漏洞，则已签名的 JWTs、SAML 断言、WebAuthn 认证信息等可被轻易入侵。  
  
ForgeRock 公司的一名安全架构师 Wadden 指出，“这个漏洞的严重性不容忽视。如果你在这些安全机制中使用 ECDSA 签名，服务器运行的是2022年4月关键补丁更新之前发布的 Java 15、16、17或18，则攻击者可轻易并完全绕过签名。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**通灵卡片**  
  
  
多年来，Java 一直支持 ECDSA 作为签名所有类型数字化文档的广泛使用的标准。Wadden 解释称，错误是因为将原生 C++ 代码中的EC 代码覆写到Java 作为Java 15 发布而引发的。  
  
Java 的 ECDSA 签名验证实现未检查和 ECDSA 签名相关的值 r 或 s 是否为0，因此可以生成一个二者均为0（编码正确）的签名值，而Java 将其作为任何信息和任何公钥的合法签名。它就相当于数字化的银行身份卡片。Wadden 将该空白银行ID卡片概念比作科幻电影《神秘博士》手中的通灵卡片。在电影中，角色通过通灵卡片愚弄人们进行合作。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**不愉快的漏洞披露过程**  
  
  
Wadden 和同事在去年11月发现了该缺陷并将其告知Oracle 及其它 Java 开发者，然而披露过程并不理想。  
  
Wadden 表示，“我对于披露流程很失望。我报告给 OpenJDK 联盟，然后掉入Oracle 黑洞。公平点说，他们确实迅速响应邮件，但总是提供最低限度的响应，直到修复方案进入 OpenJDK GitHub 移植仓库时，我才获悉修复方案详情。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**漏洞评分存在争议**  
  
  
Oracle 在发布说明中，给出的CVSS评分为 7.5，而ForgeRock 给出10分。  
  
Wadden 指出，行业躲过一劫，“很惊讶竟然没人找到并利用它，但这可能更加突出 Java 8多么稳固！大多人认为公钥签名计划是超级安全的，但实际这些实现漏洞并不新鲜。对我而言，这个漏洞最令人担心的地方在于，WebAuthn/FIDO 生态系统本质上是围绕 ECDSA P-256 签名的一个单一文化。”  
  
行业大咖 Thomas H Ptacek 称该漏洞是“年度加密漏洞”。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[黑客声称攻陷并加密白俄罗斯国家铁路的服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510323&idx=4&sn=d496153071345e3367f3fc60014857e8&chksm=ea949859dde3114f0d065410aa2ae448f92f24e82e289cbc78a131ec33aa6a5d7bb3b06134a9&scene=21#wechat_redirect)  
  
  
[多家大厂的存储设备受第三方加密软件缺陷影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509894&idx=2&sn=fde9ed390f90e1551557dbf78f35bf66&chksm=ea9496ecdde31ffa0634121ab546d89aa7d38d726a6549a37f1434b35c8bdcc0ee330e078113&scene=21#wechat_redirect)  
  
  
[Java RMI 服务易受 SSRF 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509977&idx=1&sn=58035c67d3e4f5b7ff8eb138fd8431ac&chksm=ea9496b3dde31fa5f599373712fa381150b7e61e65a2488e6333590a41850921a68c717c67d4&scene=21#wechat_redirect)  
  
  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/java-encryption-implementation-error-made-it-trivial-to-forge-credentials  
  
  
题图：Pixabay License  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMQjfQ8ZhaOGYOwiaOkCe6UVnwG4PcibqI6sJ3rojqp5qaJa0wA2lxYb0VKwria7pHqS9rJwSPSykjMsA/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
