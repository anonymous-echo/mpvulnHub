> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486308&idx=1&sn=5e27e830c39790c7273c9cc0f89f1fd9

#  紧急预警！假冒ChatGPT安装包暗藏勒索病毒，3大陷阱速看！  
原创 紫队  紫队安全研究   2025-06-19 04:01  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8RC5DX3dxrbdI78U5mj7tBEX9ibUl8iajWojH3LDRPhAy3ts0b0Vj63SfOiawypr9fdO52Tu8uficIoKQ/640?wx_fmt=png&from=appmsg "")  
  
🔍 当AI热潮遇上勒索陷阱    
  
  
ChatGPT的爆火让黑客找到了新的“财富密码”！思科Talos最新披露，三大恶意软件正伪装成AI工具安装包疯狂传播，其中伪装成ChatGPT 4.0完整版的LuckyGhost勒索病毒已感染数千台设备，中招者面临5万美元赎金威胁。这场利用AI热潮的“数字绑架”，正在搜索引擎的顶端悄悄上演……    
  
  
  
一、🚨 三大恶意软件攻击全景图    
  
  
▶ 1. CyberLock：披着商业工具外衣的勒索犯    
  
伪装手段：    
  
  伪造NovaLeadsAI商业工具网站（用.com域名冒充官方.app域名），通过SEO作弊让假网站登上搜索结果首位；    
  
攻击逻辑：    
  
  下载的安装包会加密办公文档、数据库文件，弹出勒索窗口索要5万美元门罗币，还谎称赎金将用于“巴勒斯坦/乌克兰人道主义援助”；    
  
技术特征：    
  
  无数据泄露功能却威胁公开文件，纯粹利用受害者恐慌心理敲诈。    
  
  
▶ 2. LuckyGhost：ChatGPT安装包里的“幽灵”    
  
诱饵陷阱：    
  
  命名为“ChatGPT 4.0 full version – Premium.exe”，捆绑微软Azure AI工具混淆视听（真实ChatGPT无需下载）；    
  
加密范围：    
  
  锁定Office文档、Adobe文件、数据库备份等100+格式，中招后桌面会生成名为“READ_ME_TO_RECOVER.txt”的勒索说明；    
  
传播渠道：    
  
  通过论坛、网盘分享伪装成“破解版”“增强功能包”。    
  
  
▶ 3. Numero：InVideo AI的克隆陷阱    
  
伪装技巧：    
  
  篡改文件元数据冒充InVideo AI视频编辑工具，下载后释放wintitle.exe恶意程序；    
  
潜伏机制：    
  
  同时部署批处理文件和VB脚本，可远程接收黑客指令，未来可能升级为勒索功能；    
  
IOCs披露：    
  
  思科已在GitHub公布哈希值与域名特征（搜索“Cisco Talos Numero”获取详情）。    
  
  
  
二、⚠️ 黑客的“SEO钓鱼”战术解析    
  
  
▶ 搜索引擎劫持三步骤    
  
1. 域名模仿：    
  
   注册与官方只差一个字母的域名（如novaleads.com冒充novaleads.app）；    
  
2. 关键词作弊：    
  
   在网页源代码堆砌“ChatGPT下载”“AI工具免费”等热词，欺骗搜索引擎排名；    
  
3. 流量劫持：    
  
   通过恶意广告联盟购买“AI工具”搜索关键词，确保假网站排在前三位。    
  
  
▶ 心理操控术    
  
道德绑架：CyberLock谎称赎金用于慈善，降低受害者报警意愿；    
  
时间压力：LuckyGhost倒计时显示“72小时后永久删除文件”，逼迫仓促付款。    
  
  
  
三、🛡️ 三步防御指南（附自查清单）    
  
  
▶ 企业级防护    
  
1. 域名白名单：    
  
   禁止访问非官方AI工具域名（如仅允许novaleads.app、chat.openai.com等）；    
  
2. 邮件网关强化：    
  
   拦截含“AI工具下载”“完整版ChatGPT”关键词的附件；    
  
3. 终端防护：    
  
   部署EDR工具监控.exe文件的异常加密行为（如LuckyGhost的文件遍历模式）。    
  
  
▶ 个人自查步骤    
  
1. 看域名：    
  
   官方AI工具多使用.app/.ai域名，.com域名需二次验证（如打开WHOIS查询注册信息）；    
  
2. 查文件：    
  
   右键安装包→属性→详细信息，若“公司”“版权”为空或模糊（如“Unknown”）立即删除；    
  
3. 测行为：    
  
   用VirusTotal扫描安装包，若出现“Trojan.Ransom”等标签立即隔离。    
  
  
  
四、🔚 警惕AI时代的“数字绑架”    
  
  
当黑客将AI工具变成勒索武器，每一次搜索都可能踩雷。值得注意的是，此次攻击中LuckyGhost捆绑的微软工具均为开源组件，这种“合法工具+恶意代码”的组合正成为主流攻击模式。    
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
