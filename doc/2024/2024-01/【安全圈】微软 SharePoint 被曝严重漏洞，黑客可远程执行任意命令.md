#  【安全圈】微软 SharePoint 被曝严重漏洞，黑客可远程执行任意命令   
 安全圈   2024-01-13 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
黑客攻击  
  
  
美国网络安全和基础设施安全局（CISA）最近发布了一项警告，根据现有证据，黑客正利用微软SharePoint中的提权漏洞，与另一个被评定为“关键”级别的漏洞相结合，从而能够远程执行任意命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaiaeVFN9iaeuibLoWhibLu78TPHnyR3m7DlTLYuAVEBaic4Vm2riaj5ibCa8Df440bSKG3mHRbMxUJpWoCA/640?wx_fmt=jpeg&from=appmsg "")  
  
这一漏洞的标识号为CVE-2023-29357，它允许远程攻击者使用虚假的JWT验证令牌来绕过身份验证，从而在未打补丁的服务器上获得管理员权限。微软解释称：“攻击者获取虚假JWT身份验证令牌后，可以利用这些令牌进行网络攻击，绕过身份验证，并获取已通过身份验证用户的权限。成功利用此漏洞的攻击者可以获得管理员权限。”  
  
攻击者再结合着CVE-2023-24955的漏洞，这是一个影响SharePoint Server的远程代码执行漏洞，可以让他们在SharePoint服务器上注入命令并执行任意代码。去年3月，STAR实验室的研究员Jang（Nguyễn Tiến Giang）在温哥华的Pwn2Own竞赛中成功展示了这个Microsoft SharePoint Server漏洞链，并赢得了10万美元（折合约71.7万元人民币）的奖励。研究人员在去年9月25日发表了一份技术分析报告，详细描述了这一攻击过程。仅仅一天后，另一位安全研究人员也在GitHub上发布了CVE-2023-29357的概念验证漏洞。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaiaeVFN9iaeuibLoWhibLu78TPmHVCCf6l7yuG3vKZjCPibzajoNWz2nbic0qjSkQPPCmCvDqMEvcZh8jA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】利用网络维护身份窃取出卖军工涉密文件，男子被抓！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052093&idx=1&sn=bd2e88ca0a95006880138eded19621b0&chksm=f36e363dc419bf2b6d14ff1fe9e9a4beff333b36123b673fe0fec1f75bac4905a19f0ce6d779&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaiaeVFN9iaeuibLoWhibLu78TPbkt9pj6XtEQ3NjGxTFqROoniaiaGIic7pEYdOXw23mJ1vibzAWXVr1YEAg/640?wx_fmt=png&from=appmsg "")  
[【安全圈】一单位办公系统存在HTTP弱口令漏洞，重庆网信办立马约谈](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052093&idx=2&sn=ca914268cc9c140c8f3c08a9101e7210&chksm=f36e363dc419bf2b0c96c62c4076a9b4ad75b6af8358f217490a270b74df94f3cf56ef3cd557&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaiaeVFN9iaeuibLoWhibLu78TPibyIIBZvYMLuPo41JNo9r5FhBq5eibE7bEZrntibKRzm8ZgvY6PdB9GuA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】Mandiant 的 X 账户遭到暴力破解密码攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052093&idx=3&sn=194dc8200d2ab18ed9a5789ae0aed66e&chksm=f36e363dc419bf2bde4df29321ae46bcc235cc00f1fd3b7cd92dcd317aa83317068da407c3b4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaiaeVFN9iaeuibLoWhibLu78TPZ2icpyEBXnCyia3FDop8UkvkZCEbJwH2sicUFs8WX9rYIUfVEXXd5GljA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】将 GitHub 用于恶意目的行为越来越多，目前无直观方法避免](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052093&idx=4&sn=de2386da817ae625901dae6973158655&chksm=f36e363dc419bf2b9d2b6061326cb69901a58fda22ab6f101f3e8e48aa3dfe658e41a0baa05a&scene=21#wechat_redirect)  
  
  
  
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
  
  
