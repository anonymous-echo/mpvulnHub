#  CISA警告：CrushFTP漏洞正遭利用，风险严峻！   
原创 紫队  紫队安全研究   2025-04-16 04:00  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8S0NPeJXChsaxmRhYTjeQjZUe7q1UMXS3lfTXBPJ9eyPXu792LoUXFB9ibPVSGrSusJicyLK0dSUWyg/640?wx_fmt=png&from=appmsg "")  
  
4月7日，美国网络安全与基础设施安全局（CISA）将CrushFTP产品中的一个关键漏洞——CVE-2025-31161，纳入了已知被利用漏洞（KEV）目录。这意味着该漏洞已在现实环境中被攻击者利用，且形势严峻。CISA强调，此类漏洞是恶意网络行为者频繁使用的攻击手段，会给联邦机构带来极大风险，强烈敦促所有联邦部门及其他组织，在漏洞管理工作中优先修复该漏洞。  
  
  
漏洞曝光背后的波折  
  
该漏洞由Outpost24发现，是一个严重的身份验证绕过漏洞（CVSS基础评分高达9.8）。这意味着未经身份验证的攻击者，能够借此接管运行未打补丁的CrushFTP v10或v11版本的设备。3月21日，CrushFTP公开披露了此漏洞，随后在10.8.4和11.3.1版本中进行了修复。  
  
  
然而，漏洞披露过程却出现了混乱。Outpost24与CVE编号机构之一的MITRE合作，获得了CVE标识符CVE-2025-31161，并商定了90天的保密期，以便用户有足够时间在细节公开前进行补丁更新。但在3月26日，另一个CVE编号机构VulnCheck在未与Outpost24或CrushFTP协商的情况下，发布了一个单独的标识符CVE-2025-2825。两天后，Shadowserver Foundation在X平台表示，基于公开的概念验证（PoC）利用代码，观察到针对CVE-2025-2825的利用尝试，该非营利组织还识别出至少1512个易受CVE-2025-2825攻击的未打补丁实例。4月3日，MITRE发布了CVE-2025-31161条目，而CVE-2025-2825目前在MITRE网站和美国国家漏洞数据库（NVD）上显示为“已拒绝”。Outpost24在4月2日的安全更新中指出，VulnCheck的披露导致该漏洞在用户更新系统之前就被广泛知晓，进而引发了当前的活跃利用。而VulnCheck则对MITRE拒绝CVE-2024-2825表示批评，其安全研究员Patrick Garrity在领英上称：“CrushFTP……故意要求90天内不发布CVE，实际上是试图对安全社区和防御者隐瞒该漏洞。更糟糕的是，MITRE似乎更优先考虑参与报告编写，而不是及时披露在野外被积极利用的漏洞……这开创了一个危险的先例。”  
  
  
攻击风险几何？  
  
从技术原理上看，该漏洞源于CrushFTP处理S3授权头的关键问题。漏洞涉及一个名为lookup_user_pass的布尔标志，它在身份验证链中具有双重作用。当此标志设置为true时，通过user_tools.java文件中的一个有问题的条件，可完全绕过密码验证。利用方法相对简单，攻击者只需使用简化的AWS S3风格授权头，再结合特定格式的Crush auth cookie，就能够在不提供密码的情况下，以任何已知或可猜测的用户身份进行身份验证。Huntress的研究人员早在3月30日就观察到了该漏洞在实际中的利用情况，攻击者利用该漏洞部署远程管理工具和其他恶意软件，进行后续的攻击活动。Shadowserver Foundation也检测到了针对互联网暴露的CrushFTP服务器的数十次利用尝试，并在网上识别出超过1500个易受攻击的实例。这表明，一旦攻击者成功利用该漏洞，他们就可能获取敏感信息、篡改数据，甚至完全控制受影响的系统，对企业和组织的网络安全构成严重威胁。  
  
  
应对之策  
  
对于使用CrushFTP的组织和用户而言，当务之急是立即采取行动。应尽快将CrushFTP更新到已修复该漏洞的版本，即10.8.4及以上的10.*版本，或11.3.1及以上的11.*版本。若无法立即更新，可启用非军事区（DMZ）周边网络选项作为临时解决办法。同时，要密切关注系统日志，及时发现任何异常活动迹象，因为这可能表明存在利用尝试。从更广泛的层面来看，组织应建立完善的漏洞管理机制，及时关注CISA等权威机构发布的漏洞信息，定期对系统进行安全审计，加强对网络安全态势的监控，提高整体的安全防护能力，以抵御此类不断涌现的网络安全威胁。   
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
