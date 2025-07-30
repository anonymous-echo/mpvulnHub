> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486451&idx=1&sn=f44225b916411ae0b00384f443fafb35

#  俄罗斯APT组织加剧欧洲攻击：零日漏洞与数据擦除器齐上阵  
原创 紫队  紫队安全研究   2025-07-22 03:59  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8TI2yicY7vMSLvoLUAox2nDdgRzrGn0KSyibDwTgcJfD9yQHJDicMvCsItuP1Wk2iaMicic49LX3Enrswbw/640?wx_fmt=png&from=appmsg "")  
  
2025年刚刚过半，全球网络战的“暗潮汹涌”已经让人不寒而栗。  
  
  
根据ESET于5月19日发布的《APT活动报告（2024 Q4 - 2025 Q1）》，俄罗斯对乌克兰及欧盟的网络攻击活动正在显著升级。不仅采用了多个零日漏洞（0day），更动用了新型数据擦除器（Wiper），呈现出前所未有的进攻烈度。  
  
  
💣 俄系三大“老朋友”：Fancy Bear、Gamaredon、Sandworm齐出动  
  
  
 Fancy Bear（APT28）：继续通过XSS漏洞攻击多个邮件系统，进一步拓展了“RoundPress”行动。更重要的是，他们利用了一个新的0day（CVE-2024-11182）对乌克兰公司发起了定向攻击。  
  
  
 Gamaredon（又名Primitive Bear）：被认为是FSB旗下小队，火力全开。ESET报告称，其新工具PteroBox可以通过Dropbox窃取文件，战术更为隐蔽，且恶意代码混淆能力显著增强。  
  
  
 Sandworm（APT44）：再次将目标锁定在乌克兰能源基础设施。通过AD Group Policy的漏洞推送新型Wiper“ZEROLOT”，对关键系统构成严重破坏。  
  
  
而另一支俄系组织RomCom，则祭出连环0day：  
  
  
 火狐浏览器（CVE-2024-9680）  
  
 Windows系统（CVE-2024-49039）  
  
  
多线出击，不给防守方喘息的机会。  
  
  
🌏 其他APT动态：中、朝、伊亦“各显神通”  
  
  
🇨🇳 中国APT组织：侧重政企情报与海事行业  
  
  
 Mustang Panda依旧高频活跃，利用U盘与Korplug加载器瞄准欧盟政府及海运公司。  
  
 新面孔PerplexedGoblin布设新型后门NanoSlate，目标直指中欧某国政府机构。  
  
  
🇰🇵 朝鲜APT：从“假招聘”中挖矿  
  
  
 DeceptiveDevelopment假扮区块链与金融岗位，诱骗求职者中招，部署跨平台恶意软件WeaselStore。  
  
 “老熟人”Kimsuky与Konni重新活跃，转向南韩目标，锁定外交人员。  
  
 “复出王”Andariel在消失一年后，以一波针对工业软件企业的攻击惊艳亮相。  
  
  
🇮🇷 伊朗APT：仍主攻中东  
  
  
继续围绕以色列制造业与工程行业开展间谍活动，策略稳定，未见明显升级。  
  
  
🔍 南韩APT疑似反向渗透？来自日本上传的VHDX引发关注  
  
  
ESET指出，2月28日，一个名为RadialAgent的恶意文件被上传到VirusTotal，包含诱导LNK文件与加密下载器，溯源结果指向南韩组织APT-C-60。  
  
  
这是近年来少数几次“韩国系”APT主动出击的案例之一，亦显示出东亚在网络情报战中已步入多极博弈阶段。  
  
  
🎯 BeatRex评论：网络对抗已进入“无人区”  
  
  
这份报告释放了一个明确信号：  
  
  
> 俄系APT的进攻性愈发凶狠，甚至已达“零时差”攻击水准。零日武器成规模使用、Wiper擦除器频繁登场，使得传统防御手段面临严峻挑战。  
  
  
更重要的是，攻击正在跳出传统军事冲突范围，直接触达欧洲政府、基础设施与私营企业。这将迫使整个欧洲在政策、情报、技术等层面深度调整。  
  
  
对于我们从业者而言，这也意味着：  
  
  
 检测技术必须AI化与自动化；  
  
 对战术指标（TTPs）而非简单IOC的追踪更关键；  
  
 构建自有威胁情报与反溯源体系不再可选，而是生存所需。  
  
  
🧠 最后两个思考题，留给每位安全从业者：  
  
  
1. 如果你是CISO，当你的企业客户被Fancy Bear利用0day定向攻击，你能提前识别还是事后追溯？  
  
2. 我们的防御体系，是靠“盖房子”，还是靠“听见锤子响”？  
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
