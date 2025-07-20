> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070749&idx=1&sn=050b8e30630112c924e35a27ee30ecd3

#  【安全圈】赶快升级！微信Windows端安全漏洞曝光 黑客可执行远程代码  
 安全圈   2025-07-20 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
日前，**火绒安全团队和360漏洞研究院曝光并成功复现微信Windows客户端漏洞，该漏洞可使攻击者执行远程代码。**  
  
据了解，该漏洞由“目录穿越”漏洞链与“远程代码执行（RCE）”组合触发，攻击者可利用恶意文件在用户无感知的情况下远程执行任意代码，进而实现系统控制或权限维持，从而对终端安全造成严重影响。  
  
**漏洞的技术原理在于微信客户端在处理聊天记录中的文件自动下载时，未对文件路径进行充分的校验和过滤。**  
  
攻击者可通过发送包含恶意文件的聊天消息，当被攻击方在微信中点击聊天记录时，恶意文件会自动下载并被复制到系统启动目录。  
  
利用目录穿越技术，攻击者能够绕过微信的安全限制，将恶意代码植入到Windows系统的关键目录中，实现开机自启动。  
  
当被攻击者的电脑进行重启后，**攻击方即可通过该文件对受害环境执行任意远程代码，进而实现系统控制或权限维持。**  
  
据悉，微信Windows客户端3.9及以下版本均存在此问题，建议及时从微信官网下载最新版本进行安装。  
  
![赶快升级！微信Windows端安全漏洞曝光 黑客可执行远程代码](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgCgNrpkK0TY7uJjA5krY2j8fbaHxVaSzXu1icAU7Z0yliatRqujGZmjCxzLViaKcgQ5y8cesCdk4r3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】吐鲁番首例“特种设备”系统入侵，未检气瓶竟获虚假合格证！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=1&sn=982b3d7e4a51d4cedb62c1c5ac08a23c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】LV遭黑客攻击！官方紧急通知客户立即修改密码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=2&sn=ffa655ec005a16609cb9bbeb76295759&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客利用 Apache HTTP 服务器漏洞，部署 Linuxsys 加密货币挖矿程序](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=3&sn=0ed096ca126a498dcb6caff13372e355&scene=21#wechat_redirect)  
  
  
  
[【安全圈】制造业安全警报：为何必须彻底废除默认密码？](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=1&sn=ccd1231536a99cc8c6648c5aaf2470c1&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
