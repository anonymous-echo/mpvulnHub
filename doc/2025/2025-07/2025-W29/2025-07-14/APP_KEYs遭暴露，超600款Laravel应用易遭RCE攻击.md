> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523565&idx=1&sn=bb6888cc84ad4eba9d87a3ed0137acd8

#  APP_KEYs遭暴露，超600款Laravel应用易遭RCE攻击  
Ravie Lakshmanan  代码卫士   2025-07-14 10:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRbVcfGOx8mR4bewm9ZU6yNRPPvC15rCmYgZiaz6f5hBIpxjgpG2Tjrbiazv8CWxXKmhJs79rdicL2KQ/640?wx_fmt=gif&from=appmsg "")  
  
**网络安全研究员发现一个严重漏洞，可导致攻击者利用被泄露的 Laravel APP_KEYs，在数百款应用上执行远程代码。**  
  
  
GitGuardian 公司表示，“Laravel 的 APP_KEY 对于加密敏感数据至关重要，常遭公开泄露（如泄露到 GitHub 上）。如果攻击者获得对该密钥的访问权限，他们能够利用一个反序列化漏洞在服务器上执行任意代码，将数据和基础设施置于风险之中。”  
  
GitGuardian 公司与 Synacktiv 公司协同发现，他们能够从GitHub提取2018年至2025年5月30日期间的超过26万个 APP_KEYs，从中发现600多款易受攻击的 Laravel 应用。GitGuardian 公司表示已在 GitHub 发现1万多个唯一的 APP_KEYs，其中400个已证明是起作用的。  
  
APP_KEY 是在安装 Laravel 期间生成的一个随机的32字节加密密钥。该密钥存储在该应用的 .env 文件中，用于加密和解密数据、生成安全的随机字符串、签名和验证数据以及创建唯一的认证令牌，是一个重要的安全组件。  
  
GitGuardian 公司提到，Laravel 在当前的 decrypt() 函数实现中引入了一个安全问题，它自动反序列化解密的数据，因此很可能导致远程代码执行后果。安全研究员 Guillaume Valadon 表示，“在 Laravel 应用中，如果攻击者获得 APP_KEY 并能够调用拥有恶意构造的payload的 decrypt() 函数，那么就能够在 Laravel web 服务器上实现远程代码执行后果。该漏洞最初与 CVE-2018-15133一起出现，后者影响 Laravel 5.6.30 之前的版本。然而，当开发人员通过 SESSION_DRIVER=cookie 设置明确在cookie 中配置会话序列化时，该攻击向量在更新的版本中持续存在，如在CVE-2024-55556中所示。”  
  
值得注意的是，CVE-2018-15133已遭遇 AndroxGh0st 恶意软件存在关联的威胁人员利用，后者在互联网中扫描具有配置不当的 .env 文件的 Laravel 应用。  
  
进一步分析发现，63%的 APP_KEY 暴露源自 .env 文件（或其变体），而这些文件中一般都包含其它有价值的机密如云存储令牌、数据库凭据以及与电商平台相关的机密、客户支持工具以及人工智能服务。  
  
更重要的是，约2.8万对 APP_KEY 和 APP_URL 对已被同时暴露在 GitHub 上。其中，约10%是有效的，即120款应用易受远程代码执行攻击。鉴于APP_URL 配置制定了该应用的基础URL，同时暴露 APP_URL和APP_KEY 制造了可被威胁人员用于直接访问该app、检索会话 cookie 以及尝试通过被暴露密钥进行解密的强大攻击向量。仅从仓库中删除机密是不够的，尤其是在它们已被第三方工具克隆或缓存的情况下更是如此。开发人员需要的是一个清晰的变更路径，该路径由监控系统支持，而该系统可以检测到敏感字符串在持续集成 (CI) 日志、镜像构建和容器层中的每次重新出现。  
  
GitGuardian 公司表示，“在未经适当变更的情况下，开发人员应当永远不能从仓库中删除被暴露的 APP_KEYs。正确的响应包括：立即更换受陷的 APP_KEY，用新的密钥更新所有的生产系统，并执行持续的机密监控以阻止未来的暴露情况。”  
  
这些事件类型也与更广泛的 PHP 反序列化漏洞类型一致，很多工具如 phpggc 帮助攻击者构建工具链，在对象加载过程中触发非预期行为。如通过被泄露的密钥经这些工具用于 Laravel 环境中，则可在无需攻陷该应用的逻辑或路由的情况下，实现完全的RCE。  
  
不久前，GitGuardian 公司披露称，在 DockerHub 注册表上可公开访问的 Docker 图像中发现了“令人吃惊的10万份合法机密”，包括与AWS、谷歌Cloud以及GitHub 令牌相关联的机密等。  
  
Binarly 分析了54个组织机构和3593个仓库中超过8万个唯一的Docker 镜像后，也同样发现了644个唯一机密，包括通用凭据、JSON Web Tokens、HTTP Basic Authorization 标头、Google Cloud API密钥、AWS 访问令牌和CircleCI API令牌等。  
  
该公司表示，“机密出现在多种文件类型中，包括源代码、配置文件，甚至是大型二进制文件，而这是很多现有的扫描器无法涵盖的领域。另外，整个 Git 仓库出现在容器镜像中代表了一种严重的且常常被忽视的安全风险。”  
  
但这并非全部。快速采用MCP对受企业驱动的AI应用中的代理工作流赋能已经构成了全新的攻击向量，其中一个是泄露发布在 GitHub 仓库的MCP服务器机密。具体而言，GitGuardian 公司发现其中202个服务器泄露了至少一份机密，占所有仓库的5.2%，“比在所有公开仓库上观察到的4.6%稍高”，使得MCP服务器“成为新的机密泄露源”。  
  
虽然这项研究关注的是 Laravel，但根本问题都是公开仓库中的机密不受保护，这也适用于其它栈。组织机构应当探索中心化机密扫描、针对 Laravel 的加固指南，以及管理框架中.env文件和容器机密的设计即安全模式。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[DevOps 和敏捷开发的区别是什么？](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507097&idx=3&sn=e4135ca7fce429fdac85c9a5a505d70f&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2025中国软件供应链安全分析报告》全文](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523516&idx=1&sn=0b6fc53ba92e7b5135395b67fff6a822&scene=21#wechat_redirect)  
  
  
[Ivanti Workspace Control硬编码密钥漏洞暴露 SQL 凭据](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523260&idx=2&sn=ea145b27a636bc95e9cf0045e0f89d03&scene=21#wechat_redirect)  
  
  
[已存在9年的 npm 包遭劫持，通过混淆脚本投毒提取API密钥](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522612&idx=1&sn=1083440528cb0effbb60af2d98c5dc48&scene=21#wechat_redirect)  
  
  
[LLM训练公开数据集暴露1.2万多个API密钥和密码](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522389&idx=2&sn=8e536c7ca6d3203d26b9a232e727572a&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/07/over-600-laravel-apps-exposed-to-remote.html  
  
  
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
  
