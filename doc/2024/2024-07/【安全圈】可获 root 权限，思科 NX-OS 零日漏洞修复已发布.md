#  【安全圈】可获 root 权限，思科 NX-OS 零日漏洞修复已发布   
 安全圈   2024-07-03 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞事件  
  
  
**思科修补了 4 月份曝出的 NX-OS 零日漏洞，威胁攻击者可以利用该漏洞在受影响的交换机上以 root 身份，安装未知恶意软件。**  
  
网络安全公司 Sygnia 发现并向思科方面报告了安全漏洞事件，威胁攻击者利用安全漏洞进入受害者内部系统后，收集了大量的管理员级的凭据，一边可以随时访问思科 Nexus 交换机，部署了一个此前未出现过的定制化恶意软件。  
  
此后，威胁攻击者利用这一”渠道“，便可以轻松的远程连接到受害者的设备，上传额外文件并执行恶意代码。  
  
接到漏洞通知后，思科方面立刻做出回应，指出具有管理员权限的本地威胁攻击者可以利用安全漏洞（跟踪为 CVE-2024-20399），在易受攻击设备的底层操作系统上以 root 权限执行任意命令。  
  
此外，思科相关负责人还指出，CVE-2024-20399 安全漏洞是对传递给特定配置 CLI 命令的参数验证不足造成的，使威胁攻击者能够通过将精心制作的输入作为受影响的配置 CLI 命令的参数，从而利用这一安全漏洞。  
  
**一旦威胁攻击者成功利用该安全漏洞后，就可以以 root 权限在底层操作系统上执行任意命令。**  
  
受影响设备的列表包括多个运行易受攻击的 NX-OS 软件的交换机：  
1. MDS 9000 系列多层交换机；  
  
1. Nexus 3000 系列交换机；  
  
1. Nexus 5500 平台交换机；  
  
1. Nexus 5600 平台交换机；  
  
1. Nexus 6000 系列交换机；  
  
1. Nexus 7000 系列交换机；  
  
1. 独立 NX-OS 模式下的 Nexus 9000 系列交换机。  
  
威胁攻击者还可以利用 CVE-2024-20399 安全漏洞，在不触发系统 syslog 消息的情况下执行命令，从而使其能够在被攻击的 NX-OS 设备上隐藏入侵迹象。  
  
因此，思科方面强烈建议客户应当定期监控和更改 network-admin 和 vdc-admin 管理用户的凭证。  
  
今年 4 月，思科曾警告称，自 2023 年 11 月以来，一个由国家支持的黑客组织（被追踪为 UAT4356 和 STORM-1849）一直在利用 Adaptive Security Appliance (ASA) 和 Firepower Threat Defense (FTD) 防火墙中的多个零日漏洞（CVE-2024-20353 和 CVE-2024-20359），针对全球政府网络开展名为 ArcaneDoor 的活动。  
  
当时，斯克公司多次强调，安全研究人员还发现有证据表明，威胁攻击者至少从 2023 年 7 月起就针对这些零日安全漏洞测试和开发了漏洞利用程序。之后，威胁攻击者利用这些安全漏洞安装了未知的恶意软件，使其能够在被入侵的 ASA 和 FTD 设备上留下“后门”。  
  
值得一提的是，思科指出尚未确定威胁攻击者用来入侵受害者网络的初始攻击载体。  
  
上个月，Sygnia 称 Velvet Ant 在一次网络间谍活动中利用定制恶意软件攻击了 F5 BIG-IP 设备，在这次攻击活动中，威胁攻击者利用对受害者网络的持续访问，在长达三年的时间里“偷偷”窃取了大量的敏感客户和财务信息。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xG0fkcpdIpmfI1a46JPwcS7kASB3O0JUF3WPiamOsFB9GSibtqU0jicudbg/640?wx_fmt=jpeg "")  
[【安全圈】B站、小红书崩了冲上热搜，阿里云回应](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062466&idx=1&sn=893b1ad979f3829744b10bf36d2445c6&chksm=f36e6f42c419e6545b1780b268ffcac2a45b75b982317ee6e8b17a79713a8a8ff0b07ebe14b2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljj9HEMyo2iaeKjeKeYiaIvj2OENLhW6ljKbKsAiauje6Ww7tuWHeeMdlngOtAAr4PZPVyusJp7FWarg/640?wx_fmt=jpeg "")  
[【安全圈】澳大利亚男子炮制虚假航空公司WIFI骗取乘客账户凭证](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062466&idx=2&sn=eb5901a40b0ce569b391c2509f29bf81&chksm=f36e6f42c419e654aa22a4d58ce39eecd6320fed3ba8ef2d74a967c4afdf8c8a44670ad98dd7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xGX1aSPSlwFqa8cUGAtyAngJDe2JSzdBy2pa28KnVfsQnCazrY87osOA/640?wx_fmt=jpeg "")  
[【安全圈】数百万 OpenSSH 服务器可能遭受远程 regreSSHion 攻击（CVE-2024-6387）](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062466&idx=3&sn=4dfe5314c316497a5472075715addb64&chksm=f36e6f42c419e6545ff5723e21946f0585f854c86b309bc58c4b329798deb87d9c2d854f8a9c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xGdDN9zXWVeOYNu0qMAyKPvNHPWtUribIoQQ9XdeKBCRibuXhWSmjpibbEA/640?wx_fmt=jpeg "")  
[【安全圈】影响超六百万人！美国一企业遭 LockBit 勒索软件攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062466&idx=4&sn=94a51092a4c2e8009cd101689599ee4b&chksm=f36e6f42c419e6545df8df3c891b3c47ad55859088479f2152d7c673a6979ebaee88961106e5&scene=21#wechat_redirect)  
                                                                    
  
  
  
  
  
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
  
  
