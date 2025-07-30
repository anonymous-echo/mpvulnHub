> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486416&idx=1&sn=e60df8335b42941d78f718f7af74bba3

#  高级持续威胁（APT）的最新动态与可靠信息源整理  
原创 紫队  紫队安全研究   2025-07-14 04:00  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8RcsH8qc4VicibHxoDlDSlxx9G8GgHb4spwkOzpVjLVdHMFLl0gjYEvxeElhufkReZd3u3XIPIicm9xA/640?wx_fmt=png&from=appmsg "")  
  
高级持续威胁（APT）的最新动态与可靠信息源整理，涵盖近期攻击活动、防御技术突破及专业订阅渠道，帮助您及时掌握全球APT威胁态势：  
  
  
🔥 一、近期重大APT攻击活动  
  
1. 俄罗斯APT28（Fancy Bear）对乌克兰的新攻击    
  
   手法：通过Signal加密聊天发送伪装成验收单（`Акт.doc`）的恶意文档，诱导启用宏后植入BeardShell和SlimAgent恶意软件，实现屏幕监控、数据窃取和持久控制。    
  
   特点：利用俄乌混合语言降低怀疑，精准模仿工作流程；攻击链全程无文件落地，规避传统检测。  
  
  
2. 伊朗APT35（Educated Manticore）的AI钓鱼攻击    
  
   目标：以色列记者、网络安全专家。    
  
   技术：使用AI生成无语法错误的钓鱼邮件/WhatsApp消息，伪造高管助理身份，引导至虚假Google登录页窃取凭据及2FA码。结合React框架高度仿冒合法页面。  
  
  
3. 巴基斯坦APT36（透明部族）针对印度国防的Linux攻击    
  
   创新点：首次发现针对印度政府推广的BOSS Linux系统，通过钓鱼邮件投递恶意`.desktop`文件，后台下载Go语言编写的ELF后门程序`BOSS.elf`，窃取军事数据。  
  
  
4. 印度背景DoNot APT组织升级攻击欧洲外交部    
  
   工具：新型恶意软件LoptikMod伪装成PDF（`notflog.exe`），通过Google Drive链接传播，创建计划任务维持持久访问，窃取外交敏感信息。  
  
  
5. 中国“夜鹰”组织（APT-Q-95）利用Exchange漏洞    
  
   活动：攻击政府、军工和高科技企业，利用微软Exchange高危漏洞渗透，使用美国DigitalOcean IP隐藏行踪，攻击时段集中于北京时间夜间。  
  
  
🛡️ 二、APT防御技术与行业动态  
  
1. AI驱动的安全防御突破    
  
   中国联通 & 华为：全球首个基于AI集群路由器（NetEngine 5000E-20）的APT防御系统，实现分钟级异常行为检测、自动溯源与攻击阻断，已在湖北试点成功。    
  
   奇安信AI方案：提升国家级SOC中心能力，通过AI分析百万级告警，实现Exchange漏洞攻击的主动猎捕。  
  
  
2. 政府合作与情报采购    
  
   中国国家计算机病毒应急处理中心：斥资174.3万元采购卡巴斯基非公开APT情报（年覆盖100+全球攻击事件），并部署驻场专家强化分析。  
  
  
📬 三、推荐APT情报订阅源  
  
专业机构与平台  
  
| 来源                | 特点                  | 获取方式                     |  
  
| Intel 471           | 深度分析APT组织战术（如Silver Fox、Fog勒索软件关联活动）       | 官网订阅付费报告                 |  
  
| 奇安信威胁情报中心  | 揭露中国活跃APT组织（如“夜鹰”），提供IOC特征库               | 官网/X平台（@RedDrip7）          |  
  
| 紫队安全研究        | 解析APT攻击链（如APT28的Signal攻击），提供实操防御指南         | 微信公众号                     |  
  
| CERT-UA公告         | 乌克兰官方APT预警（俄乌冲突相关攻击权威分析）                 | 官网/邮件订阅                   |  
  
  
开源情报（OSINT）与社区  
  
X平台账号：    
  
  `@RedDrip7`：发布APT攻击特征（如Exchange漏洞利用域名）    
  
  `@Trellix Labs`：披露DoNot APT等组织技术细节    
  
安全媒体：    
  
  工业安全网（Industrial Cyber）：聚焦关键基础设施APT攻击（如Fog勒索软件事件）    
  
  CN-SEC中文网：翻译全球APT报告（如伊朗APT35、DoNot组织分析）    
  
  
💎 四、总结建议  
  
优先订阅：政府CERT公告（如CERT-UA）+ 商业威胁情报（如Intel 471）结合，覆盖公开与深度情报。    
  
技术跟踪：关注深信服、微步等企业的AI防御方案，应对无文件攻击和社交工程陷阱。    
  
应急响应：对钓鱼邮件、Signal/Teams消息中的陌生文件执行沙箱扫描，禁用Office宏策略。    
  
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
