> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324846&idx=4&sn=f1d0bf41e03a0e999487db8bcdacbf1a

#  600余个Laravel应用因GitHub泄露APP_KEY面临远程代码执行风险  
 FreeBuf   2025-07-14 11:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3iboRVmw4QbAUKcqcIPQ0d4Ezpx3yiaSJRx4l0xkEHSd0h3MglpN4icVQ4RkAmL8vKAusQhzMucVib6qw/640?wx_fmt=png&from=appmsg "")  
  
  
网络安全研究人员发现一个严重安全问题：攻击者可利用泄露的Laravel框架APP_KEY密钥，对数百个应用实施远程代码执行攻击。  
  
  
**Part01**  
## 密钥泄露引发连锁反应  
##   
  
GitGuardian公司表示："Laravel的APP_KEY本应用于加密敏感数据，却经常在GitHub等平台公开泄露。攻击者获取该密钥后，可利用反序列化漏洞在服务器上执行任意代码，危及数据和基础设施安全。"  
  
  
该公司与Synacktiv合作，在2018年至2025年5月30日期间从GitHub提取了超过26万个APP_KEY，并识别出600多个存在漏洞的Laravel应用。统计显示，GitHub上存在超过1万个独立APP_KEY，其中400个被验证为有效。  
  
  
APP_KEY是Laravel安装时生成的32字节随机加密密钥，存储于应用的.env文件中。该密钥不仅用于数据加解密，还涉及安全字符串生成、数据签名验证以及身份认证令牌创建，是核心安全组件。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iboRVmw4QbAUKcqcIPQ0d4EjwicU9TVom6RrMLUpaFKpYwKznMRliaIddmoG7GNWLpYBwpNBBPsnlgw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part02**  
## 反序列化漏洞持续威胁  
  
  
GitGuardian指出，Laravel当前decrypt()函数的实现存在安全隐患——该函数会自动反序列化解密数据，为远程代码执行打开方便之门。  
  
  
安全研究员Guillaume Valadon解释："在Laravel应用中，若攻击者获取APP_KEY并能通过精心构造的恶意载荷调用decrypt()函数，就能在Web服务器上实现远程代码执行。"  
  
  
该漏洞最初记录为CVE-2018-15133，影响5.6.30之前版本的Laravel。但通过CVE-2024-55556可见，当开发者使用SESSION_DRIVER=cookie配置会话序列化时，新版Laravel仍存在此攻击向量。  
  
  
值得注意的是，与AndroxGh0st恶意软件相关的威胁组织已利用CVE-2018-15133漏洞，通过扫描互联网上.env文件配置不当的Laravel应用实施攻击。  
  
  
**Part03**  
## 多重敏感信息连带泄露  
  
  
深入分析显示，63%的APP_KEY泄露事件源自.env文件（或其变体），这些文件通常还包含其他高价值机密：云存储令牌、数据库凭证，以及电商平台、客服工具和AI服务的相关密钥。  
  
  
更严重的是，GitHub上同时暴露了约2.8万组APP_KEY与APP_URL配对信息。其中约10%验证有效，导致120个应用面临简易远程代码执行攻击风险。由于APP_URL指定应用基础地址，同时泄露这两项配置会形成强力攻击向量，威胁者可借此直接访问应用、获取会话cookie，并尝试用泄露密钥解密。  
  
  
**Part04**  
## 密钥轮换与持续监控  
  
  
GitGuardian强调："开发者绝不能简单删除仓库中暴露的APP_KEY，正确做法包括：立即轮换受损密钥、在生产系统更新新密钥、实施持续密钥监控以防再次泄露。"开发者需要建立清晰的轮换机制，并监控CI日志、镜像构建和容器层中的敏感字符串重现。  
  
  
这类事件也属于PHP反序列化漏洞的广义范畴。攻击者使用phpggc等工具构建gadget链，在对象加载时触发非预期行为。配合泄露的Laravel密钥，此类攻击无需突破应用逻辑或路由即可实现完整远程代码执行。  
  
  
**Part05**  
## 容器镜像成新风险源  
  
  
此前GitGuardian曾披露，在DockerHub公开可访问的镜像中发现"惊人的10万个有效密钥"，包括AWS、Google Cloud和GitHub令牌。Binarly对54个组织、3539个仓库的8万余个独立Docker镜像分析同样发现644个独特密钥，涵盖通用凭证、JWT、Google Cloud API密钥等。  
  
  
密钥出现在源代码、配置文件甚至大型二进制文件等多样场景中，这正是现有扫描器的盲区。容器镜像内包含完整Git仓库的情况，更是常被忽视的重大安全隐患。  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iboRVmw4QbAUKcqcIPQ0d4EPpsvy6Kc263XPZJ0WnXGnmQdbia0gqiaF8icMibiakHYAKKFibHkoOmO2qYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part06**  
## 新兴AI工作流带来新挑战  
  
  
企业级AI应用中快速普及的模型上下文协议（MCP）也催生了新型攻击向量——GitGuardian发现202个MCP服务器仓库存在密钥泄露，占全部仓库的5.2%，略高于公共仓库4.6%的平均泄露率，使MCP服务器成为"密钥泄露新源头"。  
  
  
虽然本次研究聚焦Laravel，但公开仓库中未受保护的密钥问题普遍存在于各类技术栈。企业应考虑实施集中式密钥扫描、Laravel专项加固指南，以及跨框架的.env文件和容器密钥安全设计模式。  
  
  
**参考来源：**  
  
Over 600 Laravel Apps Exposed to Remote Code Execution Due to Leaked APP_KEYs on GitHub  
  
https://thehackernews.com/2025/07/over-600-laravel-apps-exposed-to-remote.html  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324737&idx=1&sn=8f0843cf1d51ac50bd1eae4a5f0e4c87&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
