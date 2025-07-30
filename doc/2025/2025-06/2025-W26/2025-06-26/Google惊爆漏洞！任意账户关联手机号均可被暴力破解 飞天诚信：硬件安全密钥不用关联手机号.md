> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NDE1MjU2Mg==&mid=2649877196&idx=1&sn=19c499e2cf0110b58c8949023e55495a

#  Google惊爆漏洞！任意账户关联手机号均可被暴力破解 飞天诚信：硬件安全密钥不用关联手机号  
原创 飞天诚信  飞天诚信   2025-06-26 09:23  
  
近日，谷歌紧急修复了一个令人震惊的安全漏洞——攻击者只需知道谷歌账户显示的部分手机号码，就能通过暴力破解技术获取完整的手机号码。整个过程最快仅需 5 秒钟，而且受害者完全不会收到任何通知。如果与谷歌账户关联的手机号码泄露，用户可能面临更加严重的网络安全威胁，例如 SIM 交换攻击。攻击者可以冒充受害者，欺骗电信运营商将手机号转移到攻击者控制的 SIM 卡上。一旦成功，他们就能接收所有短信验证码和密码重置链接，进而全面接管谷歌账户。谷歌账户（Gmail、云端硬盘、照片等）若被攻击者接管，依赖这些服务的高价值账户（例如，使用 Gmail 接收重置密码的银行账户）也可能随之沦陷。  
  
攻击者利用谷歌账户恢复系统中的薄弱环节，通过精心设计的攻击链，可以精确获取目标用户的手机号码。整个过程分三步：  
- 第一步：获取显示名称 。攻击者创建一个 Looker Studio 文档，将其所有权转移到目标用户的 Gmail 地址。完成转移后，目标的谷歌显示名称会直接出现在攻击者的 Looker Studio 界面，而用户完全不会收到任何通知。  
  
- 第二步：获取部分手机号 。攻击者通过谷歌的 “忘记密码” 流程，输入目标邮箱地址。系统会显示与该账户关联的部分手机号码（通常只显示最后两位数字），如 “•• ••••••03”。攻击者可由此确认号码对应的国家。  
  
- 第三步：暴力破解完整号码 ：这一步的核心是滥用谷歌一个已弃用的用户名恢复表单（accounts.google.com/signin/usernamerecovery）。它原本用于帮助基础设备用户恢复账户，但缺乏现代防滥用保护措施。  
  
发现该安全漏洞的新加坡安全研究员使用专门开发的工具，利用 IPv6 地址轮换技术绕过谷歌的基础速率限制，每秒可发起高达 40,000 次查询请求；结合 Google 的 libphonenumber 库生成有效号码格式，根据国家 / 地区模式缩小搜索范围，实现高效破解。经过实际测试，破解美国号码耗时约 20 分钟，而破解新加坡号码最少只需要 5 秒钟。  
  
此前 FBI 发出过警告，提醒用户不要在社交媒体上公开手机号。这一漏洞进一步突显了手机号作为安全薄弱环节的危险性。  
虽然该漏洞已被谷歌已修复，但手机号作为账户恢复方式仍存在固有风险。用户可采取以下措施增强账户安全：  
- 移除不必要的恢复号码 ：定期访问谷歌安全设置，删除不再使用或非必需的恢复手机号；  
  
- 警惕异常通信 ：对索要密码或验证码的 “谷歌” 来电或短信保持警惕，谷歌绝不会主动索取这类信息；  
  
- 定期检查账户活动 ：定期查看谷歌账户的 “安全事件” 页面，监控可疑登录行为；  
  
- 考虑使用专用邮箱 ：对于谷歌账户恢复，使用单独的、未公开的电子邮箱比手机号更安全；  
  
- 启用更安全的 MFA ：优先选择能抵御 SIM 交换攻击的 MFA，例如硬件安全密钥（[#FIDO]()  
 Security Key），避免完全依赖短信验证。  
  
[#BioPass]()  
 FIDO2是飞天诚信的“FIDO2+指纹”硬件安全密钥产品，配置指纹模组，有效防止非授权用户盗用；产品安全性满足 NIST SP 800-63B 中最高级别（AAL3）的要求，保障指纹数据安全存储不泄露。用户可以通过 USB-A 或 USB-C 接口将 BioPass FIDO2连接到电脑或手机，快速、安全地完成 “无密码” 登录。值得一提的是，使用BioPass FIDO2 硬件安全密钥，用户无需担心自己的手机号会暴露给互联网平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/nB7GRqGZJUkNGDoJfEpsZBlboLgLIic9BJISoe5UUkPApMLrl9ogp91zT5ySLOeq3qhSym86RBuCf4xp5CtzPGw/640?wx_fmt=jpeg&from=appmsg "")  
  
在享受科技便利的同时，我们也要时刻警惕潜在的安全风险。守护数字安全，从每一个细节开始。希望每一位用户都能重视账户安全，采取必要的防护措施，让科技更好地为我们的生活保驾护航，安心享受数字化时代的便利。  
  
——THE END——  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/nB7GRqGZJUkBHxaRrwq019Tmyjgd7mU6q74TeSbRXXmnv6poygsXVIee1YUKib5bVH73rEJy9ibJFMWuWWew2Bdg/640?wx_fmt=jpeg&from=appmsg "")  
  
[FBI Warning!超18亿Gmail用户面临AI威胁 飞天诚信：最好使用两个FIDO Security Key](https://mp.weixin.qq.com/s?__biz=MjM5NDE1MjU2Mg==&mid=2649876829&idx=1&sn=3cbd044f209b52a31edca33416d46940&scene=21#wechat_redirect)  
  
  
[科普：“防钓鱼MFA”从何说起？都有哪些？](https://mp.weixin.qq.com/s?__biz=MjM5NDE1MjU2Mg==&mid=2649876964&idx=1&sn=2ec416545ea149da8794aa9e688adf0b&scene=21#wechat_redirect)  
  
  
[微软发现新型“钓鱼攻击”！飞天诚信：使用防钓鱼的MFA——FEITIAN FIDO Security Key](https://mp.weixin.qq.com/s?__biz=MjM5NDE1MjU2Mg==&mid=2649876957&idx=1&sn=1ce5cac9ed8081146b3b1d7492246b42&scene=21#wechat_redirect)  
  
  
[Gmail将改用二维码扫描"根除钓鱼攻击风险" 名校发来二维码钓鱼邮件 飞天诚信：不知攻，焉知防？](https://mp.weixin.qq.com/s?__biz=MjM5NDE1MjU2Mg==&mid=2649876802&idx=1&sn=7bcdfe5b2552ec04fac77badc1783b3c&scene=21#wechat_redirect)  
  
  
