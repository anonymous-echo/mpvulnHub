> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323083&idx=2&sn=542afbafc16938bf81c4a6946e67cfef

#  FreeBuf周报 | Meta暗中追踪数十亿安卓用户；GitLab 曝高危漏洞组合  
FreeBuf  FreeBuf   2025-06-14 10:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJ1UiaObonmWJbuLyoLXdutZ6T0GL6AXwFA0IHVJ9Tl93JicaeTmN55VJBw0JKrJg4sQXdypbdzqibg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**📚Meta暗中追踪数十亿安卓用户，并规避了传统隐私保护措施**  
  
**😈GitLab 曝高危漏洞组合：攻击者可实现完全账户接管**  
  
**🎠CyberEYE木马利用PowerShell和注册表操作禁用Windows Defender**  
  
**🛡微服务安全防护：分布式系统最佳实践**  
  
**☁️威胁狩猎入门指南：专家级主动网络安全策略**  
  
📧微软Outlook路径遍历漏洞允许攻击者远程执行任意代码  
### 🖥️UEFI安全启动遭突破，高危漏洞CVE-2025-3052威胁数百万PC  
### 📱谷歌账户恢复漏洞致攻击者可获取任意用户手机号  
### 💻新型供应链恶意软件攻击 npm 和 PyPI 生态，全球数百万用户面临风险  
### 🏦新型安卓银行木马正在全球蔓延，可完全控制安卓设备  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5NY7KgXpwrAo5WHiaX2SOibeoicce3vxyZozGALjYSLtYPrDiceL0UV2D3A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
###   
  
  
Meta暗中追踪数十亿安卓用户，并规避了传统隐私保护措施  
###   
  
Meta与Yandex利用安卓本地主机套接字，通过WebRTC技术静默追踪用户浏览数据，关联身份信息，规避隐私防护。该技术影响全球数亿用户，覆盖超578万网站，最终因浏览器厂商封禁被迫终止，暴露安卓跨应用数据共享风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxzFfLHg6yAttiakHGZTHcIQQDhibnODrjQrqQOYl51Jd6mLrhZ9qHHoIw/640?wx_fmt=jpeg&from=appmsg "")  
  
###   
  
GitLab 曝高危漏洞组合：攻击者可实现完全账户接管  
###   
###   
  
### GitLab曝高危漏洞，攻击者可完全接管账户，入侵开发基础设施。涉及多个版本，CVSS评分超8.0，包括HTML注入和XSS漏洞。紧急发布补丁，建议立即升级，防止数据泄露和CI/CD破坏。  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxBLlYjfFdvFxichpDEuKDKCb0x4iaRebVSpSicZpBuFZFT6bicPfCNvwRUA/640?wx_fmt=jpeg&from=appmsg "")  
###   
  
  
CyberEYE木马利用PowerShell和注册表操作禁用Windows Defender  
###   
###   
  
###   
  
CyberEYE新型木马通过PowerShell和注册表操作完全禁用Windows Defender，利用Telegram作为C2基础设施，具备键盘记录、数据窃取等功能，易用性强且隐蔽性高，对Windows系统构成重大威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxPw1gHcZYsibveMFd33lctvB2KusooAxuzI3JKNOWIjjMKf6UmKgZDLw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微服务安全防护：分布式系统最佳实践  
###   
###   
  
###   
  
微服务架构带来可扩展性和敏捷性，但面临分布式安全挑战。需实施多层次安全措施，包括认证授权、双向TLS、动态密钥管理和全面监控，平衡安全与灵活性。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38DtAPtkeoBKLW2FEcTvZWWDvW3nfDYtWXIQ1wyiboODO39O5OypxQKSGA6iax5zTndQQic2J1BmzVxg/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
###   
  
  
威胁狩猎入门指南：专家级主动网络安全策略  
###   
###   
  
###   
  
现代网络安全需转向主动威胁狩猎，结合MITRE ATT&CK框架、SIEM系统和SIGMA规则等工具，通过假设驱动方法预判入侵。整合机器学习与威胁情报，实现自动化检测与人工分析结合，提升复杂威胁识别能力，缩短威胁驻留时间。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxJG77dImIic9K7279WcEP5dibne4nibd4Zz4j55TB6fHo1vleyXJfh8Rfg/640?wx_fmt=jpeg "")  
  
  
微软Outlook路径遍历漏洞允许攻击者远程执行任意代码  
###   
###   
  
###   
  
###   
  
微软Outlook存在高危漏洞CVE-2025-47176（CVSS 7.8），允许低权限用户本地触发远程代码执行，影响机密性、完整性和可用性。微软暂未发布补丁，建议加强监控并准备快速更新。  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkx4Fc7mgGJicCdiae3nn5wr8gNRck8XNwib1q9ia6yVDsGeQophiaoicsLBfGA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
UEFI安全启动遭突破，高危漏洞CVE-2025-3052威胁数百万PC  
###   
  
###   
  
###   
  
###   
  
高危漏洞CVE-2025-3052（CVSS 8.2）影响UEFI安全启动，攻击者可利用微软签名的易受攻击组件Dtbios-efi64-71.22.efi，通过NVRAM变量执行任意写入，完全禁用安全启动。多数Windows/Linux设备受影响，建议撤销二进制文件签名并修复漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkx6xk1ibEO467tELHvchnaNf7umquvX9tIJbHGhJiagwTN9NibHQRQDhbEw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
谷歌账户恢复漏洞致攻击者可获取任意用户手机号  
  
###   
  
###   
  
###   
  
###   
  
谷歌账户恢复系统存在高危漏洞，攻击者可暴力破解获取用户手机号。利用无JS接口绕过防护，通过IPv6和令牌复用规避限制，效率高达每秒4万次。谷歌已修复漏洞并提升奖励至5000美元，凸显遗留系统安全风险。  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxxcyicpmxfZibVL4Xe668DZ7883Y3dGQlmdFlSianicXpiatmHicP2LU1bTiaA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
新型供应链恶意软件攻击 npm 和 PyPI 生态，全球数百万用户面临风险  
  
###   
  
###   
###   
  
###   
  
###   
  
GlueStack等12个软件包遭供应链攻击，植入恶意代码可执行命令、窃取信息，每周下载量近百万次。另有npm恶意包可删除应用目录，PyPI出现伪装Instagram工具的凭证窃取程序，已下载数千次。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icEcpvEXsIoib9NvMxeHdnt46GkNctuMVdpvgx6maPQXymbqK4ibwSlLaaS82B6UzndRMrCYxSVE4icQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
新型安卓银行木马正在全球蔓延，可完全控制安卓设备  
  
###   
  
###   
###   
  
###   
  
###   
  
新型安卓银行木马Crocodilus全球蔓延，通过伪装广告传播，可绕过Android 13+安全限制，操控设备通讯录并窃取加密货币私钥，威胁多国金融安全。  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkx8EaIVBLGdOBTDR5AweiaqJpsPe0Re28zOEEPjaqKIZVwNKNmZ7PPuicA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5Ce9OricKgAogLRlHYat9jaelbVESLOylPBnQQrU63TlHEs2zCbdNrKg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**本周好文推荐指数**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
###   
  
  
全新视角下的 Java：一种全新的方式实现完美 dump lsass  
###   
###   
  
### 传统C/C++加载器面临EDR全面封杀，Java借助JNA调用WinAPI实现免杀，利用字节码非PE特性绕过静态检测，天然免疫沙箱，实战成功dump lsass并加密，主流杀软无告警，展示Java在系统层攻击的潜力。  
  
![1749799579_684bd29bb3073957bca9a.png!small?1749799580128](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxccGpnKGl12cyCGGK1CvF05yUwZ8skSwAmwAJLxbwZORDuPIXHh81Ww/640?wx_fmt=jpeg&from=appmsg "")  
  
  
容器安全：基于甲方视角容器安全用例  
###   
###   
  
### 特权容器和API暴露易引发主机控制风险，需禁用特权模式、限制资源访问、验证镜像完整性，并实施强认证授权机制，防止容器逃逸和DoS攻击。  
  
![1749799614_684bd2be3a3ee9a56fd0f.png!small?1749799614631](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkx30DGwSiaY6LqkwvFcN0V1YAAdwiarmwI1ADdeTEXmpYt5wJKd9Uj12rg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Redis未授权漏洞复现汇总  
###   
###   
  
###   
  
### Redis未授权漏洞复现指南：涵盖未授权访问、SSH公钥写入、Webshell上传、主从复制RCE等利用方法，提供防护建议与工具推荐，适合学习测试。  
  
![1749799647_684bd2df5223e05c8c4f7.png!small?1749799647122](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxrNyxQWe4nXpMyRThusPx0cf2gNhMfRKuvUWBv73LgX3Ydk0VsXYTSA/640?wx_fmt=jpeg&from=appmsg "")  
###   
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322946&idx=1&sn=c9cbbd848459bfe0a36fa121ff364ad0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
