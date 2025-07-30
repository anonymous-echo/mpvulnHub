#  【安全圈】Windows 远程桌面服务漏洞允许攻击者执行远程代码   
 安全圈   2024-12-12 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
2024 年 12 月 10 日，微软披露了Windows 远程桌面服务中的一个严重漏洞，能够让攻击者在受影响的系统上执行远程代码，从而对系统机密性、完整性和可用性构成严重威胁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhg3ib7zk68VY9JW3cHTnvlWztiaOuGQJ5Dc1XtyjbXuc8FCNOWZaJquZ3sDkz8Wn0D90CrcbGHgk9A/640?wx_fmt=jpeg&from=appmsg "")  
  
该漏洞被跟踪为 CVE-2024-49115，CVSS 评分为 8.1，由昆仑实验室的研究员 k0shl发现。漏洞影响Windows Server 的多个版本，包括Windows Server 2016、Windows Server 2019、Windows Server 2022和Windows Server 2025。  
  
漏洞源于两个关键缺陷：  
- CWE-591：在锁定不当的内存中存储敏感数据  
  
- CWE-416：释放后使用  
  
攻击者可通过连接到具有远程桌面网关角色的系统并触发竞争条件来利用此漏洞。这会产生 “free-after-free”  情况，从而执行任意代码。  
  
值得注意的是，这种攻击不需要用户交互或权限，但其高度复杂性使得没有高级技术技能的攻击者不太可能成功利用该漏洞。  
  
目前所有受影响的版本都已作为微软 2024 年 12 月 "星期二补丁"更新的一部分，打上了相应的安全补丁。虽然漏洞利用代码的成熟度目前尚未得到证实，也没有证据表明存在主动利用或公开披露的情况，但其潜在影响仍然很大。成功利用后，攻击者可通过远程代码执行完全控制目标系统。  
  
此漏洞反映了与远程桌面协议 （RDP） 等远程访问技术相关存在的持续性风险。虽然目前还没有主动利用漏洞的报告，但这一漏洞的严重性凸显了立即采取行动保护系统免受潜在攻击的必要性，包括将 RDP 访问限制在受信任的网络、启用网络级身份验证（NLA）和监控可疑活动。  
  
参考来源：  
Windows Remote Desktop Services Vulnerability Let Attackers Execute Remote Code  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】2024下半年软考成绩查询入口崩溃了](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066561&idx=1&sn=527bdc12fc0a05c258c2907be053bcf6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】TikTok提交紧急动议 试图暂缓美国“不卖就禁”法令生效](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066552&idx=1&sn=7117c874b6af75a48c5f2d9226b17c88&scene=21#wechat_redirect)  
  
  
  
[【安全圈】SaaS巨头被勒索攻击，泄露680GB数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066552&idx=2&sn=ad4dff7bd56837a042a1598d6a445249&scene=21#wechat_redirect)  
  
  
  
[【安全圈】俄罗斯APT组织打击乌克兰国防企业](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066552&idx=3&sn=6ed80d1c092b19865bd0f426af66ef48&scene=21#wechat_redirect)  
  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
  
  
