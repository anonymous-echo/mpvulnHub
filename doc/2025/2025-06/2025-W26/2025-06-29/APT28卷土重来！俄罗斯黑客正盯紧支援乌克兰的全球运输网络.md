> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486358&idx=1&sn=7fd8696642015a9a171f76599ab9a06b

#  APT28卷土重来！俄罗斯黑客正盯紧支援乌克兰的全球运输网络  
原创 紫队  紫队安全研究   2025-06-29 03:59  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8TFrUn9zMrDViav1f11NqDySq8srZ5EnyRNSibEgj45HO3Vbu5k5lpcnlIMI1B6HEn5XAfBOYmZIQpw/640?wx_fmt=png&from=appmsg "")  
  
【2025年5月22日】多国网络安全机构联合发布预警：俄罗斯国家黑客组织APT28（又称Fancy Bear）正在加剧对西方物流与科技公司的网络攻击，目标直指——乌克兰军事援助情报！  
  
  
这不是简单的网络渗透，这是在战火背后展开的“数字战役”。  
  
  
  
🎯 攻击目标：谁在俄罗斯的“黑客瞄准镜”中？  
  
  
据通报，APT28主要盯上了与乌克兰援助运输与协调相关的组织，涵盖：  
  
  
 ✈️ 空运、🚢 海运、🚄 铁路物流公司  
  
 🖥️ IT服务与系统集成商  
  
 🛡️ 军备运输调度系统、边境摄像监控设施  
  
 📡 战略通信与监控设备供应商  
  
  
受影响国家包括：🇺🇸美国、🇫🇷法国、🇩🇪德国、🇵🇱波兰、🇳🇱荷兰 等多数北约国家与乌克兰盟友。  
  
  
  
🧬 他们怎么入侵？APT28的战术比你想象得更“老辣”  
  
  
俄罗斯GRU情报总局第85特别服务中心（26165部队）掌控APT28，长期以“国家级APT战术”著称。  
  
  
最新攻击手段包括：  
  
  
| 战术           | 描述                                                                                                         |  
  
| |  |  
  
| 🎯 暴力破解与猜测凭证 | 通过自动化方式攻击邮箱、VPN、后台入口                                                                                       |  
  
| 🎣 鱼叉式钓鱼攻击   | 精准定制邮件诱导高管点击含木马链接或伪装附件                                                                                     |  
  
| 🐛 利用高危漏洞入侵  | 利用多个高危CVE：<br>- Microsoft Outlook (CVE-2023-23397)<br>- WinRAR漏洞 (CVE-2023-38831)<br>- Roundcube邮件系统多个0Day |  
  
| 🧬 横向移动与权限提升 | 使用PsExec、RDP、Impacket等原生工具深度渗透内网                                                                           |  
  
| 📦 数据窃取与持久化  | 修改注册表、邮箱权限，窃取运输调度、军援时程、货物清单等核心数据                                                                           |  
  
  
  
📷 更可怕的是：APT28正控制乌克兰边境摄像头！  
  
  
报告显示，APT28还渗透了乌克兰边境及关键交通节点的IP摄像头系统。  
  
  
> 🚨 已有81%的被攻陷设备位于乌克兰本土，可供黑客实时监控援助物资的移动与运输路线。  
  
  
这不仅威胁前线安全，更可能导致精准打击、定点伏击等军事风险升级。  
  
  
  
🦠 黑客武器库：HEADLACE 与 MASEPIE 恶意程序  
  
  
在此次行动中，APT28使用了自研恶意工具，包括：  
  
  
 HEADLACE：具备高级凭证窃取与文件外传能力  
  
 MASEPIE：支持“隐蔽通信管道”与远程命令执行，配合“土生土长技术”混合部署（Living-off-the-land）  
  
  
APT28的攻击方式融合定制恶意代码与操作系统原生命令，避开传统防火墙、杀毒软件的监测。  
  
  
  
🛰️ 网络空间已是现代战争主战场  
  
  
此次APT28行动，是俄罗斯长期“混合战争”战略的延续。网络间谍+军事目标+情报导向+实时打击的组合，正在成为现代冲突的新范式。  
  
  
而APT28之外，2024年还曝出另一个与GRU有关的新兴组织 Cadet Blizzard（第161训练中心，29155部队）参与全球破坏行动。  
  
  
  
🔐 写在最后：如果你在物流、信息、IT服务等行业，请立刻提升安全等级！  
  
  
 检查是否部署已知CVE的补丁  
  
 启用MFA/2FA，多因素认证  
  
 严格邮箱与VPN访问控制  
  
 定期审计远程访问、注册表权限与管理员账户活动  
  
 加强内部威胁情报与APT预警联动  
  
  
  
📣 今天他们攻击的是运送武器的卡车，明天也可能是你企业的ERP系统或摄像头。  
  
  
🌐 战争的前线早已从战壕转向了交换机、网关与摄像头。  
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
