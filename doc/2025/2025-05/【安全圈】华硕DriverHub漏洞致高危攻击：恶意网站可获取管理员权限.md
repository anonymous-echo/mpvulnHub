#  【安全圈】华硕DriverHub漏洞致高危攻击：恶意网站可获取管理员权限   
 安全圈   2025-05-13 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliahNbIK8S3wCbSNO0wHRWX0jubRyrqhQgba8URAaicCgaBDK4tia5iaf4WdzZgOF5oZSM9MJqT1WFFxg/640?wx_fmt=png&from=appmsg "")  
#### 漏洞概述  
  
华硕官方驱动管理工具**DriverHub**  
被曝存在**远程代码执行漏洞（CVE-2025-3462/CVE-2025-3463）**  
，允许恶意网站通过诱导用户访问特定页面，直接以**系统管理员权限**  
在目标设备上执行任意命令。  
  
该漏洞由新西兰安全研究员Paul（网名“MrBruh”）发现。DriverHub是华硕主板预装的背景服务，默认运行于本地53000端口，用于自动检测和安装最新驱动，但绝大多数用户对其存在毫无察觉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliahNbIK8S3wCbSNO0wHRWX0FokXcy4ffPAKjZVJBgp1L07Ju0gJ9rwP51aBoUzmwIhgInJlU5zq5g/640?wx_fmt=png&from=appmsg "")  
#### 攻击原理：双漏洞组合利用  
1. **源验证绕过（CVE-2025-3462）**  
  
1. DriverHub  
  
仅通过检查HTTP请求头中的Origin  
字段验证请求来源，但验证逻辑存在缺陷。攻击者可伪造包含driverhub.asus.com  
的域名（如driverhub.asus.com.mrbruh.com  
）绕过限制。  
  
1. **静默提权执行（CVE-2025-3463）**  
  
1. UpdateApp  
接口允许从.asus.com  
域名下载并静默运行.exe文件，且未清理签名校验失败的临时文件（如.ini配置和恶意载荷）。攻击者可诱骗用户访问恶意网页，通过本地服务端口下发指令，下载华硕官方签名的安装包（如AsusSetup.exe  
）并加载恶意配置，进而以管理员权限执行攻击代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliahNbIK8S3wCbSNO0wHRWX0NlicgGW9BgfZiaiaEY07CrZZTqKExQAtxEZbfdM1PyGoiczJLl1Zek24SA/640?wx_fmt=png&from=appmsg "")  
#### 华硕回应与用户应对  
- **修复时间线**  
：华硕于2025年4月8日收到报告，4月18日发布补丁，但未向研究人员   支付漏洞赏金。  
  
- **官方声明矛盾**  
：**CVE描述**  
称漏洞“仅影响主板，不涉及笔记本或其他终端”，但实际所有   安装DriverHub的设备均受影响。  
**安全公告**  
则明确建议用户立即升级，通过软件内“立即更新”按钮获取补丁。  
  
- **风险缓解**  
：  
更新至最新版DriverHub（版本号需高于修复补丁）。  
  
   无需该功能的用户可通过BIOS彻底禁用DriverHub服务。  
  
#### 行业警示  
  
此事件再次暴露**供应链预装软件的安全风险**  
：  
1. **权限滥用**  
：厂商工具常以高权限运行，却缺乏严格的代码审计。  
  
1. **隐蔽性威胁**  
：用户对后台服务无感知，难以及时防护。  
  
1. **企业响应缺陷**  
：华硕CVE描述的误导性可能削弱漏洞威胁认知，延缓修复进程。  
  
安全专家建议：**禁用非必要预装服务，定期检查企业端点的后台进程与开放端口**  
。截至目前，尚无证据表明漏洞已被大规模利用。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】黑客利用微软 SharePoint 版 Copilot AI  漏洞窃取密码及敏感数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069594&idx=2&sn=46d82e1f37361ed9ed403fbd5798d394&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌将因其位置追踪行为向德克萨斯州支付 14 亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069594&idx=3&sn=78803ef238e4a597494358edf81f03e5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】面对DNS盗版屏蔽令 Google、Cloudflare 和 OpenDNS 的应对各有不同](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069594&idx=4&sn=82a563a61202ce51e029277d9c898488&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Microsoft Teams 将禁止在会议期间截屏](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069558&idx=1&sn=2987948da429aca3ced7a01f29894350&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
