#  【安全圈】Veeam备份软件漏洞引发全球勒索软件攻击浪潮   
 安全圈   2024-07-16 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
  
  
漏洞 CVE-2023-275327（CVSS 评分为 7.5）会影响 Veeam Backup & Replication 组件。攻击者可利用此问题获取存储在配置数据库中的加密凭据，从而可能导致访问备份基础结构主机。  
  
该漏洞已于 2023 年 3 月得到解决，不久后，该问题的 PoC 漏洞利用代码被公开发布。  
  
专家观察到，俄罗斯网络犯罪集团 FIN7 自 2023 年 4 月以来一直在利用该漏洞，黑莓的研究人员报告说，2024 年 6 月，一名威胁行为者使用 Akira 勒索软件瞄准了一家拉丁美洲航空公司。对目标网络的最初访问是通过安全外壳 （SSH） 协议进行的，攻击者在第二天部署 Akira 勒索软件之前泄露了关键数据。他们滥用合法工具和生活异地二进制文件和脚本 （LOLBAS） 进行侦察和持久性。数据泄露完成后，攻击者部署勒索软件来加密受感染的系统。Akira 是一种勒索软件即服务 （RaaS），已被 Storm-1567（又名 Punk Spider 和 GOLD SAHARA）使用，该组织自 2023 年以来一直活跃。对 Remmina 相关域的 DNS 查询等指标表明攻击者可能是基于 Linux 的用户。  
  
以下是 Akira 攻击链的第 1 天和第 2 天：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgAjUUHuyCsLmlTC8MOiaqmFzr0ynauJvCmndGFf8orLChJ22YuWpj9Mldfib41fM7PJXqZP1KOKNLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgAjUUHuyCsLmlTC8MOiaqmFjUicG2ps4st7lKMWdnQJwWPQBVZicDcQmbcPJFzulP9faR32W7PGEdPw/640?wx_fmt=png&from=appmsg "")  
  
在对一家拉丁美洲航空公司的攻击中，攻击者首次通过路由器 IP 地址的 SSH 对未打补丁的 Veeam 备份服务器进行可见访问。专家认为，攻击者利用公开可用的漏洞漏洞CVE-2023-27532。  
  
进入网络后，攻击者创建了一个名为“backup”的用户，并将其添加到管理员组以保护提升的权限。攻击者部署了合法的网络管理工具高级 IP 扫描程序来扫描通过“路由打印”识别的本地子网。  
  
攻击者通过访问 Veeam 备份文件夹来控制 Veeam 备份数据，并压缩和上传各种文件类型（包括文档、图像和电子表格），以收集机密和有价值的信息。攻击者使用免费的 Windows 文件管理器 WinSCP 将数据泄露到他们控制的服务器。  
  
从初始登录到数据泄露的整个操作仅用了 133 分钟，最终命令在 UTC 时间下午 4：55 结束。  
  
“当NetScan在主Veeam备份服务器上运行时，通过防病毒用户界面（UI）和命令行在虚拟机主机上禁用了防病毒（AV）保护，”BlackBerry发布的报告写道。“现在，持久性已经完全到位，威胁行为者试图使用Veeam备份服务器作为控制点，在全网范围内部署勒索软件。我们看到文件“w.exe”（Akira 勒索软件）被部署在受感染的 Veeam 服务器的各种主机上。  
  
Group-IB 研究人员还发现了一个勒索软件组织利用 Veeam Backup & Replication 实例中的漏洞。专家报告称，2024 年 4 月，EstateRansomware 团伙使用 PoC 漏洞利用代码针对漏洞 CVE-2023-27532。  
  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/E1iauzlb2BTnCYYPh6uHR3cuNlj8w7lElicsvO69wlFYzsaicUNQbrxXQjFHOQUNqHfCNicHgR0vXpznDpD28U1YNw/640?wx_fmt=other "")  
[【安全圈】北京海淀警方发布三起严厉打击涉网违法犯罪案例](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062855&idx=1&sn=27b4b857044bf5c755c24ace893b08c4&chksm=f36e68c7c419e1d1b32b4011dd559af1fb96e5ff893bd2ad3340720d2d84250143dffe84c3e5&scene=21#wechat_redirect)  
       
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljEvq6JMKxw0l9iaNQkVrkO0kUrVXDZic4icHTlDmPtX3zHo3jcnFict2HAOfS3gUOrlUeBV5KNRvLYJQ/640?wx_fmt=png "")  
[【安全圈】超过200万人在针对Snowflake的攻击中受到影响](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062855&idx=2&sn=3c2c8d6ddee79de100f73c2355e9c66c&chksm=f36e68c7c419e1d1c636a1bed5f06d36fd64a51e93befeb6461bbcba34d809251a3c6217707d&scene=21#wechat_redirect)  
       
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljEvq6JMKxw0l9iaNQkVrkO0eEIq3ficjxwibY8Fy9dqY61ET1Q628xPCrXibaf2Xiaibwwc2vVvhLGwk5Q/640?wx_fmt=jpeg "")  
[【安全圈】仅需22分钟，刚公开的漏洞PoC就被黑客利用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062855&idx=3&sn=4c3de4434af430e0c1bf88432232e34e&chksm=f36e68c7c419e1d1128549035da33ad4cf4c1bb36d639f2d442955f9089eaa3fb0de3e55db5d&scene=21#wechat_redirect)  
                 
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljEvq6JMKxw0l9iaNQkVrkO0aLTUtFFvVIF2p03YwSA2qscKs1b1Oicic3Dvheiaw2wKnyUCRazHqXHsg/640?wx_fmt=png "")  
[【安全圈】在 NuGet 供应链攻击中发现的 60 个新恶意包](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062855&idx=4&sn=af237d0ccdd8fb7934d1d00b73d63c2d&chksm=f36e68c7c419e1d1d538489766170dd820ab47ac0bf2f75094bab25f7d06aa5c6b75538032c9&scene=21#wechat_redirect)  
             
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
