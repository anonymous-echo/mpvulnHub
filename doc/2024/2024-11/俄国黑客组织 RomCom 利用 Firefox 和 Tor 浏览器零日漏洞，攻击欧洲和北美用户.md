#  俄国黑客组织 RomCom 利用 Firefox 和 Tor 浏览器零日漏洞，攻击欧洲和北美用户   
原创 紫队  紫队安全研究   2024-11-30 03:59  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8S1O8mcSNJ2P1yQicwibdZzd2yLqSf23to0UQeXp3esWOESj8DX0UlWTRRyHibRzKDNyaCvwNaDvaanw/640?wx_fmt=png&from=appmsg "")  
  
近期，网络安全公司 ESET 发布了一份引人关注的报告，披露俄罗斯黑客组织 RomCom 利用 Firefox 和 Tor 浏览器 中的两个零日漏洞，对欧洲和北美的用户发起了一系列高精准攻击。    
  
  
这些攻击不仅不需要用户交互，还可以在用户毫无察觉的情况下入侵他们的设备，展现了黑客的高度隐蔽性与精确打击能力。  
  
  
🎯 漏洞详情：两个零日漏洞如何被利用？  
  
  
1️⃣ CVE-2024-9680：Firefox 动画时间轴漏洞    
  
  
漏洞位置： Firefox 动画时间轴（Animation Timelines）功能。    
  
影响范围： 该漏洞可导致代码执行，使攻击者能够控制浏览器内容进程。    
  
  
该功能主要用于开发者调试和管理 CSS 动画，但 RomCom 组织利用这一漏洞，实现了对浏览器沙箱的逃逸。  
  
  
2️⃣ CVE-2024-49039：Windows 任务计划程序权限提升漏洞    
  
  
漏洞位置： Windows 任务计划程序。    
  
漏洞影响： 允许低权限用户逃逸 AppContainer 沙箱，并以中等权限运行代码，从而进一步扩大对系统的控制。    
  
  
🚨 攻击链揭秘：从伪造网站到全面入侵  
  
  
RomCom 的攻击流程极具隐蔽性和连贯性，主要包括以下几个步骤：  
  
  
1. 创建假网站：黑客首先搭建了一个假网站，诱骗受害者访问。    
  
2. 触发漏洞：一旦受害者使用存在漏洞的浏览器访问该网站，漏洞被触发，启动恶意代码执行。    
  
3. DLL 注入逃逸沙箱：利用Reflective DLL 注入技术绕过浏览器沙箱，进而下载并执行 RomCom 的后门程序。    
  
4. 后门控制：受害者的设备被安装后门程序后，攻击者可完全远程控制设备，并窃取敏感数据。  
  
  
攻击者的恶意服务器域名中常带有“redir”或“red”等前缀，以增加伪装性，例如 journalctd[.]live 和 correctiv[.]sbs。  
  
  
🌍 攻击范围广泛，欧洲与北美成重灾区    
  
  
ESET 报告显示，从 2024 年 10 月 10 日到 11 月 4 日，攻击者主要针对欧洲和北美的用户，每个国家最多有 250 名受害者中招。这种全球性攻击进一步显示出RomCom 的高度组织化与资源优势。  
  
  
🛡 Mozila 迅速应对，25 小时内修复漏洞    
  
  
ESET 在发现漏洞后立即与 Mozilla 进行了协调披露。Mozilla 迅速响应，仅用 25 小时便发布了补丁，显示了其强大的应急能力。相比行业标准，这一速度令人印象深刻。  
  
  
🔍 持续威胁：RomCom 的升级变种与新攻击手段  
  
  
不仅如此，Cisco Talos 的研究人员还观察到，自 2023 年末以来，RomCom 针对乌克兰政府机构和波兰实体的攻击活动持续升级。    
  
  
此次攻击中，RomCom 使用了新变种后门程序 SingleCamper，以及两款新下载器 RustClaw 和 MeltingClaw，以及基于 Rust 的后门 DustyHammock 和 C++ 后门 ShadyHammock。  
  
  
🛡 如何保护自己？    
  
  
1. 及时更新浏览器和操作系统：确保安装最新的安全补丁，避免成为漏洞攻击的目标。    
  
2. 警惕陌生链接与网站：尽量避免访问不明来源的链接，尤其是看似合法但实际未知的网站。    
  
3. 使用安全工具：部署强大的安全软件和防火墙，监控并拦截可疑活动。  
  
  
⚠️ 随着 RomCom 不断升级其攻击手段，网络威胁只会更加复杂和隐蔽。保护好您的数字资产，从一份安全意识开始！    
  
****  
****  
**推荐阅读：知识星球连载创作"全球高级持续威胁：网络世界的隐形战争"，总共26章，相信能够为你带来不一样的世界认知，欢迎感兴趣的朋友****入圈沟通交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
****  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
****  
  
  
  
