#  【安全圈】苹果 macOS 虚拟机应用 Parallels Desktop 曝漏洞未修补完全   
 安全圈   2025-03-04 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
#####   
  
安全研究员 Mykola Grymalyuk 去年曝光苹果 macOS 平台广受好评的 Parallels Desktop 虚拟机软件存在一项编号为 CVE-2024-34331 的提权漏洞。  
  
尽管 Parallels 在当年 4 月便已着手处理，并为 Parallels Desktop 推出 19.3.1 版本，但目前安全研究员 Mickey Jin 透露**官方修补措施并不完全**，黑客仍可绕过相关补丁进行攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhMb7NWibsOia2SPicAWlhBJ25uBiat6GgiaEUHwZxYB1ful4XibKB2Vaic0bVncKYwg4726QnH1djVDjHSw/640?wx_fmt=png&from=appmsg "")  
  
安全研究员 Mickey Jin 指出，他在研究 Mykola Grymalyuk 发布的信息时发现 Parallels 针对 CVE-2024-34331 推出的补丁可被绕过，原因在于**这些代码主要用于验证名为 createinstallmedia 的工具是否具备苹果公司签名，一旦确认经过苹果公司签署，便会赋予 root 权限以供后续使用**  
。因此黑客很容易利用相应手法，将所掌握的系统账户权限提升为 root 权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhMb7NWibsOia2SPicAWlhBJ253VNbXQGh7hIBncvicic1wY4GuKUW4UpQ9xA0iaR4s8uycVhnLicLl2h6Wg/640?wx_fmt=png&from=appmsg "")  
  
Mickey Jin 指出，黑客至少有两种可行方案进行攻击。其中一种是在通过签名验证后，利用检查时间与使用时间（TOCTOU）之间的时间差进行攻击，即在虚拟化平台处理验证流程时，替换为恶意版本的 createinstallmedia 达到攻击目的。  
  
另一种方式则是针对签名验证机制入手，研究人员指出这一方法与名为 anchor apple 的需求字符串有关，黑客可通过在苹果公司签名的可执行文件中注入恶意 dylib 库以绕过验证流程。  
  
IT 之家注意到，Mickey Jin 先后向漏洞悬赏项目 Zero Day Initiative（ZDI）以及 Parallels 报告此事，**但时隔半年该漏洞依然未能彻底修复，因此他决定公开披露相应漏洞**，并呼吁用户提高警惕。  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】美国追回 2021 年铀金融黑客攻击中被盗的 3100 万美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068238&idx=1&sn=f24cc0f9962f89f077b6f37fbbbb1e5f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】虚假验证码网络钓鱼活动影响超过1150个组织](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068238&idx=2&sn=c807685df25b8dd97cf78362316b2fbc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客滥用 Google 和 PayPal 的基础设施窃取用户个人数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068238&idx=3&sn=fadc819d47b14f0f312ff3b09d675f9e&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
