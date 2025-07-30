#  脆弱的Tesla汽车！第三方软件的漏洞可致汽车被黑客操控   
 网络安全应急技术国家工程中心   2024-05-20 15:32  
  
得克萨斯大学达拉斯分校（UT Dallas）网络安全专业硕士研究生Harish SG，同时也是一名活跃的安全研究人员，发现TeslaLogger（用于从Tesla车辆收集数据的第三方软件）中存在一个漏洞，该漏洞表现为明文存储的登录凭据和不安全的默认设置，可被利用来获得对TeslaLogger实例的未经授权的访问。即外部攻击者确实有可能利用这个漏洞，并最终对某人的特斯拉拥有实质性控制权。Harish SG使用censys在公共互联网上发现了超过30个teslalogger实例，这证实至少有这些Tesla汽车可以被这个漏洞形成危害。  
  
向TeslaLogger维护人员报告了该问题，后者采取了措施来降低风险。维护者已启用加密以在数据库中存储tesla API密钥和刷新令牌。因此，即使攻击者破坏了数据库或graphana，他也无法获得纯文本形式的API密钥。此外，维护者已经在管理面板中添加了身份验证。特别值得注意的是，该漏洞并不存在于Tesla车辆或Tesla基础设施内。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYFMXqUeibicA2ryzEBWnXV66aYVI0t3licjOSHu0Vubkkk8daibibyz2I3cw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
TeslaLogger漏洞发现过程  
  
在搜索有趣的汽车项目时，特斯拉汽车的开源数据记录器TeslaLogger中发现了漏洞。  
  
使用Docker将其安装到笔记本电脑上后，研究人员使用nmap来识别 MariaDB数据库（端口3306）、Graphana可视化工具（端口3000）和管理面板（端口8888）中正在运行的服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaY8sulxN788cEKGu7QNibhiaBXePZUfXDuOhxHelJMbgHPxZXZRUez72pQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Nmap结果  
  
出于对MariaDB和Graphana的兴趣，他利用DBweaver使用项目存储库中找到的默认凭据连接到数据库，并希望提取Tesla汽车API密钥，执行SQL查询以检索“cars”表中的所有数据。  
  
利用Tesla API的Tesla集成中存在漏洞，因为受损的Tesla令牌（包括访问令牌和刷新令牌）使攻击者能够完全远程控制汽车。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYTct709FibzPx1sribWmrUQcHbzq9xrZRUHs340fFZZ57WEta6AYFGctg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
数据库  
  
虽然Tesla的API采用基于角色的访问控制(RBAC)，但Tesla记录器应用程序经常请求过多的权限，从而允许攻击者利用API密钥来操纵汽车的状态（例如，添加驾驶员、解锁车门、控制气候）。  
  
即使数据库未公开，此问题仍然存在，因为存在获取API密钥的替代方法。Raspberry Pi 设备上的某些Tesla记录器实现会因疏忽而暴露API密钥而进一步加剧问题。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYicyo2eU1iaYibPRrv42TnCVuZx2u5Or72DRWuOgGXKl4103KmQBXh370g/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
需要权限才能正常运行  
  
Harish SG发现了一个具有默认凭据的易受攻击的Grafana仪表板，允许访问Tesla API令牌。TeslaLogger是用于Tesla数据记录的第三方软件，由于以纯文本形式存储凭据且默认配置不安全，因此存在漏洞。  
  
漏洞性质  
  
Harish SG发现的Teslalogger软件的漏洞是两个层面的问题。一个是归类于CWE—256 ( https://cwe.mitre.org/data/definitions/256.html ) ，即将敏感信息（例如口令、API 密钥等）以明文形式存储在数据库或数据存储中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYLs46uD69sTzYj4CIazaWFBbubbFMdZ76icpPaKs39p1CPXGCGic4XVxw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
第二个问题，是归类于CWE-1188( https://cwe.mitre.org/data/definitions/1188.html )，即该软件使用默认值初始化或设置资源，该默认值旨在由管理员更改，但默认值并不安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYROWGWIGBicwbmSanYr4NsR5mekFG352BMCOtMHibsj6c8LAJiaNCRs9JA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
开发人员经常选择默认值，使软件尽可能开箱即用、开放且易于使用，前提是管理员可以（或应该）更改默认值。然而，当默认设置不安全并且管理员不更改它时，这种易用性就会付出代价。  
  
影响分析  
  
通过利用这些漏洞，识别出超过30个易受远程攻击的TeslaLogger实例，可能授予Tesla 车辆的控制权，并在发现TeslaLogger开发人员的联系信息后，负责任地将调查结果报告给 TeslaLogger开发人员。  
  
公共互联网普查系统  
  
负责任的披露  
  
通过使用google dorking在互联网上找到这个WhatsApp电话号码，向teslalogger的开发者和维护者报告所发现的问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYROx6sZ3IWrdlb5BJiboLv0hM6kzyiaQx6GoibDzo26eQcZwZEBicN9ib4uw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
披露了TeslaLogger（特斯拉汽车的第三方软件）中的一个漏洞，如果攻击者破坏了TeslaLogger数据库，则可能允许攻击者窃取Tesla API凭证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYG7LKskFaPIWcLqAyjhGaW7F3kMY9kT8UKHHbW4xSibE0dH9f9BB31Og/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
与开发人员的沟通  
  
他与TeslaLogger维护人员合作解决了该问题，其中涉及对数据库中的API凭证进行加密并向管理窗格添加身份验证，之所有没有直接向Tesla报告该问题，因为他们过去也发现了关于另一个第三方软件的类似问题，但从Tesla收到了无益的回复。  
  
缓解措施及建议  
  
维护者已启用加密以在数据库中存储tesla API密钥和刷新令牌。因此，即使攻击者破坏了数据库或graphana，他也无法获得纯文本形式的API密钥。此外，维护者已经在管理面板中添加了身份验证。  
  
https://github.com/bassmaster187/TeslaLogger/commit/85a1680b60be97c45849eb66de094194bad3dedb#diff-f7564391a6870cf15ca7940ca2666fb1508cdb617aa075ebcc046930e372aea3  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icXcE9N7pmBJHRib4WWIwQzaYAibao8WxttpBMLGGVMBFvPkG7tvhKEdnLZzibicvcaeURaZSyBFeS128g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
建议tesla记录器软件的所有用户将该软件升级到最新版本，并在将该软件部署在云上某处并在公共互联网上公开服务时更改数据库和graphana的默认凭据。  
  
建议所有部署在云端的tesla记录器软件用户联系shodan和censys等搜索引擎网站，从其结果中删除您的服务。  
  
**参考资源：**  
  
1.https://infosecwriteups.com/hacking-into-30-tesla-cars-around-the-world-using-a-third-party-software-00957ac68c92  
  
2. https://cybersecuritynews.com/30-tesla-cars-hacked/  
  
  
  
原文来源  
：网空闲话plus  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
