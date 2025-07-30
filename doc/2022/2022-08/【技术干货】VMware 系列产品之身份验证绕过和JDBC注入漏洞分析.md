#  【技术干货】VMware 系列产品之身份验证绕过和JDBC注入漏洞分析   
 星阑科技   2022-08-29 16:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1NSkNgX8voWSJmuSUlcQtsLKWSxBUmsxRCOqbNibhhXFuhtfXiak5ibYGMcEGD9yzzIy4qVq1Q5a63IQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1NSkNgX8voWSJmuSUlcQtsLgZE9TXJrsxHuabVS0UbocSyplzJJ0pxtQQZpAzIBdZwlByjZ3qUUAQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "好看的图.png")  
  
**xxhzz**  
  
**@PortalLab实验室**  
  
  
**前言**  
  
在此前分析了CVE-2022-22972  VMware Workspace ONE Access和CVE-2022-22954 VMware Workspace ONE Access SSTI RCE之后，发现当时的安全公告中同时披露了很多cve漏洞，其中就包括CVE-2022-22955和CVE-2022-22957，之前漏洞环境也一直还在，也正好再学习分析一波。  
  
**漏洞描述**  
  
从4月6号的  
漏洞公告  
（https://www.vmware.com/security/advisories/VMSA-2022-0011.html）  
显示，VMware Workspace ONE Access 在 OAuth2 ACS 框架中有两个身份验证绕过漏洞，CVE-2022-22955就是其中一个，攻击者可通过获取OAuth2客户端的激活码，激活OAuth2客户端以此绕过身份验证；而CVE-2022-22957属于JDBC注入导致的远程代码执行，具有管理访问权限的攻击者通过可控参数构造恶意JDBC URL触发反序列化，从而执行任意命令获取系统权限。  
  
**利用范围**  
  
产品利用范围可参考https://www.vmware.com/security/advisories/VMSA-2022-0011.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KC3FLEJuibR4dc684ibia4gAlQ2zxP1j6pegqYicibftGibcVSY44sYZ7Yvww/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**漏洞分析**  
## 环境搭建  
  
漏洞环境使用的是VMware Workspace ONE Access 21.08.0.1 OVA  
  
具体搭建可参考https://mp.weixin.qq.com/s/zVYQQgDjcwJKAnX8SZJ5Cw  
## 分析复现  
### CVE-2022-22955 OAuth2TokenResourceController ACS 身份验证绕过  
  
定位com.vmware.horizon.rest.controller.oauth2.OAuth2TokenResourceController#generateActivationToken  
  
存在路径：/generateActivationToken/{id}  
  
在generateActivationToken方法中将为oauth2客户端生成激活码activationToken  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KwuoeLh54FUBZjW9T72qxuN3oBUOplJefNzV4xZFwYe9F6Gicd1KymFw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
接着在  
com.vmware.horizon.rest.controller.oauth2.OAuth2TokenResourceController#activateOauth2Client上方注解说明得很清楚，通过交换activationToken也就是前面获取到的激活码来激活oauth2客户端，获取 client ID 和 client secret，用于/SAAS/auth/oauthtoken做身份认证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KU59KUF7UVAkAZQAZLgY8vDPg7HtCdabHOTOqnUXjd92IhVvGd5HTkg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
其实也就是获取到client ID 和 client secret后就可以进行身份认证的绕过。  
  
那如果不存在如上分析的 OAuth2 客户端，也就无法利用。  
  
在默认情况下，VMware Workspace ONE Access会安装两个内部客户端。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86K16RlS5ib46jd9eSIJnyobia0VQXDbpXtZY09wXSLBBBMiaXH9YlEb1RdA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
在VMware Workspace ONE Access安装过程中，会调用com.vmware.horizon.rest.controller.system.BootstrapController类进行初始化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86K7T4wtia6czwib4LwIUUJaA2m5CAWUX7Hm26icbdXR445HrSvMKvg2nq1Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
本质上会导致com.vmware.horizon.rest.controller.oauth2.OAuth2TokenResourceController#createTenant调用createDefaultServiceOAuth2Client函数，从而创建系统范围内的oauth2 客户端。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86K1658f6p0tdhsANmia5ibjh9RWmnB00YQTx9xJoibKdo3ibibxKHsibtNzGxg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KWlgJwicV80Fs4Mhn34VvdoSyVXWupWTtOKL4jeuoiakwibtGRfl43rh9Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
通过如上分析进行漏洞复现，看看实际效果。  
  
首先通过/generateActivationToken/{id}，获取oauth2客户端激活码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KAP2aP9WebUKEictRAEPFh0mBNQmRctYYRcicGfmWAa5G2R1UeMsR0bibQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
再通过交换activation激活码来激活oauth2客户端，获取a client ID 和 client secret  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86K7Z98zvCPjvMt9r5AebFEc5wm5jXn9iahSNPDo0WzJMVIxxUp4NunziaQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
最后使用 client ID 和 client secret做身份认证，并获取到可用jwt token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KsYAibYsUkwX73jW5f649ZToEtekHzVRbUvLX7ZibMkYOTf7NfacAL1wA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
至此，可通过获取到的jwt token进行身份验证的绕过。  
### CVE‐2022‐22957 VMware Workspace ONE Access JDBC注入漏洞  
  
VMware Workspace ONE Access 默认安装PostgreSQL数据库。  
  
代码定位到com.vmware.horizon.rest.controller.system.DBConnectionCheckController.class  
  
存在doCheck函数。  
  
获取到jdbcUrl、dbUsername、encryptedPwd（加密后dbPassword）后调用dbConnectionCheckService.checkConnection  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KUyg99xsY861xTcz0cWqZZHyPJrjwfJibRIMhsiaicen2icTTogFbFF23XA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
com.vmware.horizon.datastore.impl. DbConnectionCheckServiceLmpl#checkConnection中将会调用testConnection  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KVKP1HGyRJAUuqJX6AkxjEgHB7ibJaxaowicjIavYIRAuNFBPgibLsiahhA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
而在testConnection中会继续调用FactoryHelper.getConnection  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KHoUibmHEUJ12h7fmT8wAC0wFsiazOmWIMs6iceXT0V8DMef4AWtZXOHwQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在FactoryHelper.getConnection中最终调用DriverManager.getConnection用于获取数据库的连接，而其中的jdbc URL完全可控。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wfFYMXc5G1MFRExQG2v1891XqdfTv86KyrMxBicaKOzLFnR1LmFAXFJP7UnoSVA1RuLABvpKLdqqulCw6r2WBug/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这就导致了jdbc注入，从而任意命令执行。  
  
后续利用可参考  
  
https://srcincite.io/blog/2022/08/11/i-am-whoever-i-say-i-am-infiltrating-vmware-workspace-one-access-using-a-0-click-exploit.html  
  
**修复建议**  
  
根据官方解决方案https://kb.vmware.com/s/article/88098 进行修复。  
  
**参考材料**  
  
1.https://www.vmware.com/security/advisories/VMSA-2022-0011.html  
  
2.https://srcincite.io/blog/2022/08/11/i-am-whoever-i-say-i-am-infiltrating-vmware-workspace-one-access-using-a-0-click-exploit.html  
  
3.https://su18.org/post/jdbc-connection-url-attack/  
  
4.https://kb.vmware.com/s/article/88098  
  
**更多技术干货，欢迎关注“星阑PortalLab”公众号**  
  
  
  
  
**关于Portal Lab**  
  
星阑科技 Portal Lab 致力于前沿安全技术研究及能力工具化。主要研究方向为API 安全、应用安全、攻防对抗等领域。实验室成员研究成果曾发表于BlackHat、HITB、BlueHat、KCon、XCon等国内外知名安全会议，并多次发布开源安全工具。未来，Portal Lab将继续以开放创新的态度积极投入各类安全技术研究，持续为安全社区及企业级客户提供高质量技术输出。  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492888&idx=1&sn=219ad26c37836f5cdefc5f41dea620c0&chksm=c0074884f770c192f60f651f3e0c6a0f293b38a59d9499a89cd1b9c2e2d8cbc4dd4620783ed1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492771&idx=1&sn=5bc86cbf62a83db69b1b1919ad86273b&chksm=c007493ff770c0290f199daef6b03bd09f9f85e35c5179c3ca8fe062623ecc27522b45850f0a&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492691&idx=1&sn=7f4fdf863953280d024c2ae7144badff&chksm=c00749cff770c0d98d9848f5415e2c7b395add84d39e4ab51172549c024d36cfc80af23ad43e&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247492617&idx=1&sn=103b4a185c02f1435ddcc1778bd038e6&chksm=c0074995f770c08374efe7cda4e53a8991a867e2b1b73fe05f0f4a32335756a56c77483ee75f&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
