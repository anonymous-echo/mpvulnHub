#  【安全圈】黑客利用未修补的 AVTECH IP 摄像机漏洞进行僵尸网络攻击   
 安全圈   2024-08-30 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
僵尸网络  
  
  
影响 AVTECH IP 摄像机的多年前高度严重性漏洞已被恶意行为者用作零日漏洞，以将其引入僵尸网络。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljMbr0ntrr68V1XmGSnMvI9aEreE6L67FpibyudDBoLMlD01tduHLqMqhoth8lnCMgkqtVTE70Ochg/640?wx_fmt=other&from=appmsg "")  
  
CVE-2024-7029（CVSS 评分：8.7）是“在 AVTECH 闭路电视 （CCTV） 摄像机的亮度功能中发现的命令注入漏洞，允许远程代码执行 （RCE），”Akamai 研究人员 Kyle Lefton、Larry Cashdollar 和 Aline Eliovich 表示。  
  
美国网络安全和基础设施安全局 （CISA） 于本月早些时候首次公开了安全漏洞的详细信息，强调了其低攻击复杂性和远程利用它的能力。  
  
“成功利用此漏洞可能允许攻击者以正在运行的进程的所有者身份注入和执行命令，”该机构在 2024 年 8 月 1 日发布的警报中指出。  
  
值得注意的是，该问题仍未修补。它会影响固件版本最高为 FullImg-1023-1007-1011-1009 的 AVM1203 台摄像机设备。根据 CISA 的说法，这些设备虽然已停产，但仍用于商业设施、金融服务、医疗保健和公共卫生、交通系统部门。  
  
Akamai 表示，该攻击活动自 2024 年 3 月以来一直在进行，尽管该漏洞早在 2019 年 2 月就已被公开的概念验证 （PoC） 利用。但是，直到本月才发布 CVE 标识符。  
  
“运营这些僵尸网络的恶意行为者一直在利用新的或不为人知的漏洞来扩散恶意软件，”这家网络基础设施公司表示。“存在许多公共漏洞利用或可用 PoC 的漏洞，这些漏洞缺乏正式的 CVE 分配，在某些情况下，设备仍未修补。”  
  
攻击链相当简单，因为它们利用 AVTECH IP 摄像头漏洞以及其他已知漏洞（CVE-2014-8361 和 CVE-2017-17215）在目标系统上传播 Mirai 僵尸网络变体。  
  
“在这种情况下，僵尸网络可能使用的是 Corona Mirai 变体，早在 2020 年，其他供应商就已将其与 COVID-19 病毒联系起来，”研究人员说。“执行后，恶意软件通过端口 23、2323 和 37215 上的 Telnet 连接到大量主机。它还会将字符串 ‘Corona’ 打印到受感染主机上的控制台。  
  
几周前，网络安全公司 Sekoia 和 Team Cymru 详细介绍了一个名为 7777（或 Quad7）的“神秘”僵尸网络，该僵尸网络利用受感染的 TP-Link 和华硕路由器对 Microsoft 365 帐户进行密码喷洒攻击。截至 2024 年 8 月 5 日，已识别出多达 12,783 个活跃的机器人。  
  
“这种僵尸网络在开源中以在受感染设备上部署 SOCKS5 代理而闻名，以中继针对全球许多实体的 Microsoft 365 帐户的极慢的’暴力’攻击，”Sekoia 研究人员说，并指出大多数受感染的路由器位于保加利亚、俄罗斯、美国和乌克兰。  
  
虽然该僵尸网络的名字来源于它在受感染设备上打开 TCP 端口 7777 的事实，但 Cymru 团队的后续调查揭示了可能的扩展，以包括第二组主要由华硕路由器组成并以开放端口 63256 为特征的机器人。  
  
“Quad7 僵尸网络继续构成重大威胁，展示了弹性和适应性，即使其潜力目前尚不清楚或尚未发挥，”Cymru 团队说。“7777 和 63256 僵尸网络之间的联系，同时保持着一个独特的操作孤岛，进一步凸显了 Quad7 背后威胁运营商不断发展的策略。”  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljibib6DAVHApmNb590Tn8hhchG6BNU7apvZ244Dr8Xb8we8hSniaibsk4FsjAyYUh5OmrV9FesvflXnQ/640?wx_fmt=jpeg "")  
[【安全圈】游戏玩家遭遇“黑手”，稀有“装备”频频失窃，福州警方破获“黑客”盗宝奇案！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063922&idx=1&sn=a63c6b4e41bdbfca1161943a3f4da8c1&chksm=f36e64f2c419ede4a634294d1dc6d3b5e957695039cdf343fe496ad9af9b14f606a1497054b6&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljibib6DAVHApmNb590Tn8hhcwFFfGWxjLk919mmrfSzDta2pzG6d9l8HFGrYcjOGicq5HLyiaUrRjx6w/640?wx_fmt=jpeg "")  
[【安全圈】姆巴佩号炸了！黑客发梅西落泪：C罗历史最佳，梅西不是我的goat](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063922&idx=2&sn=bbfe1f230f817372bb39266ccba1dc92&chksm=f36e64f2c419ede4183370841defd09fa45f197891efb233ec65702c1d4b927018dd452b69b7&scene=21#wechat_redirect)  
  
  
【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljibib6DAVHApmNb590Tn8hhcU2sGEczgmCWicYJ8Cib1cCct17Hl8e6x4t0faRO9EJNctdhHOYnVj4bQ/640?wx_fmt=jpeg "")  
[【安全圈】韩国黑客利用 WPS Office 零日漏洞部署恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063922&idx=3&sn=81a7b25c65525b6c22e056b4862fd75f&chksm=f36e64f2c419ede4a5d323f60a06bcb268d5be2fe49467be658fd77fdfe16b67fc071cccd488&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljibib6DAVHApmNb590Tn8hhc8SrdWxKNooUjVYV0cjibJS2LLkibBmicabH1dWMzrRqtXNu6uCmaPPjtw/640?wx_fmt=jpeg "")  
[【安全圈】Google 再提高 Chrome 漏洞赏金数额，最高可达25万美元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063922&idx=4&sn=d84ea75a78fbb31a769c8664a64275c2&chksm=f36e64f2c419ede41e7a078180ba1e86ccf0242e598bae5b3a328359e54b1ddc154a8039f40b&scene=21#wechat_redirect)  
                    
  
  
  
  
  
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
  
