> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486354&idx=1&sn=0b6895de460dea4931b4ab5de8f88918

#  APT28换套路：这只“俄罗斯间谍熊”，盯上了全球邮件服务器！  
原创 紫队  紫队安全研究   2025-06-25 04:00  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8TFrUn9zMrDViav1f11NqDyS8YdludjUUhyUs4XlbpA6TAHyuoGbKTE54vN8wdlKqTiajN393n8LR5Q/640?wx_fmt=png&from=appmsg "")  
  
🔔【安全警报】俄罗斯著名黑客组织APT28，最近似乎换了玩法——他们不再一味用鱼叉式钓鱼邮件攻击，而是悄悄盯上了暴露在公网的邮件服务器、SQL数据库与目录服务端口。  
  
  
这一次，被盯上的，除了传统政府、军方机构，连德国幼儿园、法国私立中学也未能幸免！  
  
  
  
  
 🧊 什么是APT28？  
  
  
APT28（也叫Pawn Storm、Sednit、Sofacy、Strontium）是全球最臭名昭著的国家级黑客组织之一。它与俄罗斯军方情报机构高度关联，是美国大选干预、WADA反兴奋剂机构攻击等重大事件背后的“常客”。  
  
  
他们精通网络间谍术，偏爱使用鱼叉式钓鱼邮件、恶意软件和零日漏洞，在全球各地长期潜伏、窃取情报。  
  
  
  
  
 📡 新战术：不打草惊蛇，先“扫”你一下  
  
  
根据趋势科技（Trend Micro）最新发布的报告：  
  
  
 2019年，APT28频繁扫描443端口，寻找邮件服务器和Exchange Autodiscover接口。  
  
 一旦发现目标暴露在公网，它们就尝试暴力破解账号密码，下载邮件数据，再反过来利用这些服务器发送新一轮钓鱼邮件。  
  
  
与此同时，它们还扫描了：  
  
  
 445端口（SMB）  
  
 1433端口（MS SQL Server）  
  
  
这代表APT28不只是想入侵邮箱，还可能企图攻破数据库和身份验证系统，深度入侵组织内网。  
  
  
  
  
 🎯 攻击目标“花样百出”  
  
  
APT28此次扫描的对象并不局限于“高价值”目标。  
  
  
除了传统的：  
  
  
 国防军工企业  
  
 政府机构  
  
 政党与律师事务所  
  
 世界各地高校  
  
  
它们甚至将目光投向了：  
  
  
 🇫🇷法国私立学校  
  
 🇬🇧英国中小学  
  
 🇩🇪德国幼儿园  
  
  
为什么这些非传统目标也被盯上？有分析认为，这些机构的网络防护薄弱、邮件信息未经加密，容易被当作跳板用于进一步攻击。  
  
  
  
  
 🧬 “伪装的朋友”：利用已被攻陷邮箱继续扩散  
  
  
APT28还使用了一种“社交工程升级版”战术：  
  
  
▶️ 用已经入侵的高价值目标邮箱向其联系人群发钓鱼邮件。  
  
▶️ 看起来像是熟人发来的文件或链接，骗你“自投罗网”。  
  
  
这在中东地区的军工企业中屡试不爽。  
  
  
  
  
 🤔 为什么改变战术？  
  
  
专家认为：  
  
  
1. 规避传统反垃圾邮件系统  
  
2. 扩大初始访问面  
  
3. 长期潜伏式攻击准备  
  
  
但趋势科技指出，这一战术并未显著提高邮件投递率，也许APT28正在“试水”新打法。  
  
  
  
  
 🛡️ 写在最后：你的服务器安全吗？  
  
  
APT28的“战术演化”对每一个组织都是一个警示：  
  
  
 邮件服务器暴露在公网？快检查！  
  
 Exchange、SQL服务是否开启默认端口？有没有强密码？  
  
 有没有对端口扫描行为进行实时告警？  
  
  
APT攻击不是天方夜谭，真正的对抗来自日常的配置、日志、监测和意识。  
  
  
📌 今天被攻击的是德国的幼儿园，明天可能就是你所在的企业。  
  
  
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
