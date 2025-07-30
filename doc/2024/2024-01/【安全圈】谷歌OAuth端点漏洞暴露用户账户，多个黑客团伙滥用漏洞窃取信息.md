#  【安全圈】谷歌OAuth端点漏洞暴露用户账户，多个黑客团伙滥用漏洞窃取信息   
 安全圈   2024-01-02 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
黑客攻击  
  
  
近期，多个恶意软件团伙纷纷利用一个名为"MultiLogin"的未记录的Google OAuth端点漏洞，恢复已过期的身份验证cookie，进而获取用户账户信息。即便用户已重置密码或会话过期，黑客仍能成功登录。  
  
  
会话cookie是一种特殊类型的浏览器cookie，包含身份验证信息，允许用户在不输入凭据的情况下自动登录。尽管这类cookie有时间限制，但该漏洞使得黑客能够在未经授权的情况下持续访问谷歌账户。  
  
  
Lumma和Rhadamanthys黑客团队于2023年11月下旬声称可以恢复在攻击中被盗的过期Google身份验证cookie，此举引起了严重关注。CloudSEK研究人员发表的报告详细解释了漏洞的工作原理，揭示了被大规模滥用的后果。  
  
  
漏洞的首次披露可追溯至2023年10月20日，由名为PRISMA的黑客在Telegram上发布消息。CloudSEK的逆向工程揭示，该漏洞使用了未注明谷歌OAuth端点的“MultiLogin”，通过接收账户ID和auth-login标记向量来同步不同Google服务之间的帐户。  
  
  
该漏洞利用了Gaia Auth API的一部分，用于在多个Google网站中设置浏览器中的Chrome帐户的Google身份验证cookie。此请求触发条件是cookie中的帐户与浏览器中的帐户不一致。  
  
  
通过窃取的token，威胁行为者可以重新生成过期的Google Service cookies，即使用户重置密码，身份验证cookie也可多次重新生成。  
  
  
Lumma stealer于11月14日首次利用该漏洞，其开发人员采用了黑盒技术，如用私钥加密token:GAIA对，以保护机制不被竞争对手复制。随后，其他团队如Radamanthys、Stealc、Medusa、RisePro和Whitesnake相继效仿，并发布了更新版本以逃避Google滥用检测措施。  
  
  
目前，至少有6个黑客团队声称能够使用此API端点重新生成Google cookie。由于Google尚未确认MultiLogin端点是否被滥用，该漏洞的利用状况和修复措施仍存在不确定性。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggVVTh160kkobxcKqFh6EiccNR69mLxNIEEuH5iccVAnTnCPYckPRyOOSIprnwJASoYhpN4tK1SibHQ/640?wx_fmt=jpeg "")  
[【安全圈】原价 270 多元的会员，只需 1 元？有人疯狂下单！真相大跌眼镜](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051308&idx=1&sn=e5fa177a1bf5d5fa330208736d72174f&chksm=f36e3b2cc419b23ac9b4ce3104c042230617327c708dc995ffc37f3da5b837fffcd3e349f82a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylggVVTh160kkobxcKqFh6EickIwX3OTjdlsPmPAwF43jUianicIqOy1FXPxpDfiaw4uicyMmWNZAV4hickQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】Steam热门游戏遭破解，玩家需警惕安全风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051308&idx=2&sn=c75bec7bbcbf0701ed4d19b776433f1c&chksm=f36e3b2cc419b23a0663d33e854e7c5ee3f56c8b03f31096fb7420087a933610d47055e53dbd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylggVVTh160kkobxcKqFh6Eicy4lZzDqiafFG0n6ycbCmPPCTYlzINWIUCrR75td9ibNdazZsQq8hYKTQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】现象级车辆App遭网络攻击，泄露数百万用户数据](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051308&idx=3&sn=c23f6fb5f76241e1a0217c61c80e365e&chksm=f36e3b2cc419b23a691ffbe8e1c3d54baf6a5ea6cb0ea6994f80daf0886354b57243d10cecd6&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylggVVTh160kkobxcKqFh6EicCy1qicXRz787ibibFGkFibiabZU3kZztCcznwVLUFFsZCKUIrZozibV447hA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】执法部门采取强有力手段，BlackCat 勒索软件网站已关闭](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050429&idx=4&sn=0960ca950a61d6f7c2ad13f6a505af75&chksm=f36e3fbdc419b6ab40d8090bab5907c08298925ec11fd20dd83ae32b41797a6265b091b8653e&scene=21#wechat_redirect)  
  
  
  
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
  
  
