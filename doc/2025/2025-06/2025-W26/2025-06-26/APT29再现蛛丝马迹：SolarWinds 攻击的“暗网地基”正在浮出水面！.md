> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486355&idx=1&sn=3660825a88ccb79ee3e2aaa50372d114

#  APT29再现蛛丝马迹：SolarWinds 攻击的“暗网地基”正在浮出水面！  
原创 紫队  紫队安全研究   2025-06-26 04:00  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8TFrUn9zMrDViav1f11NqDySerM5I09JYuGnSWqr0Zt6OLgzQV8ShT0WwFrCkibgwtQczUI3AUGiaeBw/640?wx_fmt=png&from=appmsg "")  
  
💥 SolarWinds事件，这一波及全球的超级网络攻击，已过去一年多。但幕后黑手——俄罗斯国家级黑客组织APT29（又名Cozy Bear），至今仍在各国安全研究员的追踪名单上。  
  
  
近日，威胁情报公司 RiskIQ 发布新报告，揭示出更多APT29隐藏极深的网络基础设施，为揭开这一攻击行动的“深水区”打开了一道口子。  
  
  
 🔍 事件回顾：SolarWinds——一场“精英级别的渗透行动”  
  
  
2020年底，SolarWinds Orion 平台被曝遭入侵，攻击者通过供应链手段，在官方更新包中植入恶意代码“Sunburst”。全球上千家机构中招，其中包括：  
  
  
 美国财政部、国土安全部等关键政府部门  
  
 微软、英特尔、赛门铁克等科技巨头  
  
 多个金融、能源、学术机构  
  
  
攻击持续时间超过 9个月未被察觉，被美国政府正式归因于俄罗斯对外情报局（SVR）旗下的APT29。  
  
  
 🧠 RiskIQ新发现：APT29玩的“是情报对抗，不是脚本小子游戏”  
  
  
RiskIQ旗下 Atlas 威胁情报团队通过大规模网络遥测，结合 IoC 数据，挖掘出：  
  
  
 56% 更多APT29掌控的攻击基础设施  
  
 18个此前未被发现的C2控制服务器  
  
  
这些新发现，主要通过分析其HTTP响应特征（banner）、SSL证书、主机地理位置和活动周期得出。  
  
  
 🧬APT29用了一些非常“高级”的技巧来隐藏自己：  
  
  
| 技术             | 说明                       |  
  
  |  
  
| 🕸️ 混淆域名购买     | 利用第三方、域名拍卖平台购买，避免直接关联    |  
  
| ⌛ 利用过期域名       | 回购旧域名，复用其历史信誉            |  
  
| 🇺🇸 在美国本地托管C2 | 减少被“国外主控”系统识别的可能性        |  
  
| 🔄 分阶段使用不同恶意代码 | 阶段一、阶段二植入程序完全不同，混淆追踪     |  
  
| 🕑 延迟通信机制      | 初始植入程序“潜伏”两周后随机通信，规避日志分析 |  
  
  
 🧩 命名混战：APT29就是“信息战高手”  
  
  
APT29在不同攻击阶段有多个名字：  
  
  
 UNC2452  
  
 StellarParticle  
  
 Nobellium  
  
 Dark Halo  
  
  
这不是“研究员搞混了”，而是APT29故意为之——通过伪装和混淆战术，让各安全机构难以统一归因与防御策略。  
  
  
 📈 为什么这次发现这么重要？  
  
  
1. 扩大了攻击面调查范围：更多基础设施曝光，可能意味着还有被攻击目标尚未发现。  
  
2. 揭示APT29下一步动向线索：网络结构是行动“地基”，挖出它，才能理解未来可能的攻击路径。  
  
3. 为全球安全团队提供全新IoC，加强防御部署。  
  
  
美国政府相关部门已被通知这一重大发现，调查正在进一步扩大。  
  
  
 🔐 写在最后：战争不再是导弹，而是日志里的一行代码  
  
  
APT29不是黑客组织，是国家行为体。他们的行动，不只是为了攻击，更是为了：  
  
  
 情报控制  
  
 地缘优势  
  
 长线渗透与操控  
  
  
SolarWinds事件告诉我们：一个软件供应链、一个不设防的邮件服务器，都可能成为国家间网络战争的“后门”。  
  
  
📣 今天他们攻击的是SolarWinds，明天可能就是你企业的供应商。  
  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
