#  【安全圈】微软Telnet服务器被曝0-Click漏洞：无密码即可控制系统   
 安全圈   2025-05-05 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
科技媒体 borncity （4 月 30 日）发布博文，报道称微软 Telnet 服务器存在高危漏洞，**无需有效凭据即可远程绕过身份验证，直接访问系统，甚至能以管理员身份登录。**  
  
****  
该漏洞名为“0-Click NTLM Authentication Bypass”，攻击者可利用 Telnet 扩展模块 MS-TNAP 中 NTLM 身份验证过程的配置错误，远程绕过身份验证，直接以任意用户身份（包括管理员）访问系统。  
  
  
这一漏洞被归类为高危级别，其概念验证（PoC）代码已在网络上发布。不过该漏洞仅影响较旧的 Windows 系统，从 Windows 2000 至 Windows Server 2008 R2。这些系统早已退出主流支持，仅部分通过扩展支持更新（ESU）获取有限维护。  
  
  
专家建议检查并禁用 Telnet 服务器功能。据悉，在这些 Windows 系统中，Telnet 服务器默认未启用，但若被手动激活，则存在巨大安全隐患。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhmLgOOL8k8Fic9iaqHu2icsmDzhkyR9yF0rpj5R1CrhQYIJRrHHthxNNhRCfcaFm4PZtiaKicQUeibWH9w/640?wx_fmt=jpeg "")  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】天津市破获一起“扫码领鸡蛋”个人信息贩卖案](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069434&idx=1&sn=e2f2f03c03e7a3796d3f1c7f7ba7936b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】TensorRT-LLM高危漏洞可导致攻击者远程执行代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069434&idx=2&sn=d5df9c61dfde5337bda54bd34af3c2af&scene=21#wechat_redirect)  
  
  
  
[【安全圈】7 个恶意 PyPI 包滥用 Gmail 的 SMTP 协议执行恶意命令](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069434&idx=3&sn=b1aa5eaeefb5067a413edc8afb26842b&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
