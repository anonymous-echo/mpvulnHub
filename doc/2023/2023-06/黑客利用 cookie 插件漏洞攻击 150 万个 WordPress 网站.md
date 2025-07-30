#  黑客利用 cookie 插件漏洞攻击 150 万个 WordPress 网站   
 网络安全应急技术国家工程中心   2023-06-01 14:41  
  
持续的攻击针对名为 Beautiful Cookie Consent Banner 的 WordPress cookie 同意插件中的未经身份验证的存储跨站点脚本 (XSS) 漏洞，该插件具有超过 40,000 个活动安装。  
  
在 XSS 攻击中，威胁参与者将恶意 JavaScript 脚本注入易受攻击的网站，这些脚本将在访问者的 Web 浏览器中执行。  
  
影响可能包括未经授权访问敏感信息、会话劫持、通过重定向到恶意网站感染恶意软件或完全破坏目标系统。  
  
发现这些攻击的 WordPress 安全公司 Defiant 表示，该漏洞还允许未经身份验证的攻击者在运行未修补插件版本（最高并包括 2.10.1）的 WordPress 网站上创建流氓管理员帐户。  
  
此次攻击活动中利用的安全漏洞已于 1 月份通过 2.10.2 版的发布进行了修补。  
  
“根据我们的记录，该漏洞自 2023 年 2 月 5 日以来一直受到频繁攻击，但这是我们所见过的针对它的最大规模攻击，”威胁分析师 Ram Gall 表示。  
  
“自 2023 年 5 月 23 日以来，我们已经阻止了来自近 14,000 个 IP 地址的近 300 万次针对超过 150 万个站点的攻击，并且攻击仍在继续。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibBzgdxpcpnIHocxyPicKWOjpZ7xXrjxKVgaWyqypIEvFdXtbia5sIho3VfvlzjK4icOTiaor138x59MA/640?wx_fmt=png "")  
  
尽管这种持续的攻击活动具有大规模性质，但 Gall 表示，威胁参与者使用了一种配置错误的漏洞利用，即使针对运行易受攻击的插件版本的 WordPress 站点，该漏洞也可能不会部署有效负载。  
  
即便如此，建议使用 Beautiful Cookie Consent Banner 插件的网站管理员或所有者将其更新到最新版本，因为即使攻击失败也可能会破坏存储在 nsc_bar_bannersettings_json 选项中的插件配置。  
  
该插件的补丁版本也已更新，以在网站成为这些攻击的目标时进行自我修复。  
  
尽管当前的攻击可能无法向网站注入恶意载荷，但该攻击背后的威胁行为者可以随时解决这个问题，并 potentially 感染仍然暴露的任何网站。  
  
上周，威胁行为者也开始探测运行 Essential Addons for Elementor 和 WordPress Advanced Custom Fields 插件的 WordPress 网站。这些攻击始于发布证明概念 (PoC) 漏洞之后，该漏洞允许未认证的攻击者在重置管理员密码并获取特权访问后劫持网站。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/hackers-target-15m-wordpress-sites-with-cookie-consent-plugin-exploit/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
