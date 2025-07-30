#  【安全圈】SonicWall SMA 100系列发现多个漏洞紧急安全更新   
 安全圈   2025-05-08 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
SonicWall发布了安全公告,详细说明了影响其安全移动访问(SMA)100系列产品的多个漏洞。该咨询强调了三个重要的身份验证后漏洞,这些漏洞可能允许攻击者破坏受影响的系统。  
  
vulnerabilities该咨询概述了以下关键漏洞:  
  
CVE-2025-32819:身份验证后SSLVPN用户任意文件删除漏洞。此漏洞允许具有 SSLVPN 用户权限的远程身份验证攻击者绕过路径遍历检查并删除任意文件。这可能导致重新启动到工厂默认设置,导致重大中断。此漏洞的CVSS评分为8.8,表明严重程度很高  
  
vulnerabilityCVE-2025-32820:身份验证后SSLVPN用户路径遍历漏洞。此漏洞使具有 SSLVPN 用户权限的远程身份验证攻击者能够注入路径遍历序列,使 SMA 设备上的任何目录都可写。此漏洞的 CVSS 评分为 8.3。  
  
CVE-2025-32821:身份验证后SSLVPN管理远程命令注入漏洞。此漏洞允许具有 SSLVPN 管理权限的远程身份验证攻击者注入 shell 命令参数以在设备上上传文件。此漏洞的 CVSS 评分为 6.7。  
  
vulnerabilities这些漏洞影响以下 SonicWall SMA 100 系列产品:SMA 200、210、400、410 和 500v,特别是那些运行版本 10.2.11-75sv 和更早版本。  
  
需要注意的是,“SonicWall SSL VPN SMA1000系列产品不受这些漏洞的影响。  
  
SonicWall强烈建议受影响的SMA 100系列产品的用户升级到固定版本,以解决这些漏洞。固定版本为10.2.1.15-81sv及更高。  
  
除了升级之外,SonicWall 还建议将以下解决方法作为安全措施:  
  
启用多因素身份验证(MFA):SonicWall强调“MFA具有防止凭证盗窃的宝贵保护,并且是良好安全态势的关键衡量标准。该咨询进一步澄清了“无论MFA是直接在设备上还是在组织中的目录服务上启用的,它都是有效的。  
  
在 SMA100 上启用 WAF。  
  
重置密码: 重置可能通过 Web 界面登录设备的任何用户的密码。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】微软才是“风险”！用户吐槽Win11强制启用BitLocker](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069486&idx=1&sn=3b6221c00c65809839cef14716a2ecc8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】欧盟将于 2027 年禁止匿名加密账户和隐私币](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069486&idx=2&sn=524a8ddb9a5b8cf7de04cfa2ae4eeb05&scene=21#wechat_redirect)  
  
  
  
[【安全圈】未经身份验证的 DoS 漏洞导致 Windows 部署服务崩溃，目前尚无补丁](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069486&idx=3&sn=4f5c262b7363fc3d020faaae04c66c05&scene=21#wechat_redirect)  
  
  
  
[【安全圈】虚假的DSA电子邮件诱骗用户安装ScreenConnect RAT](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069486&idx=4&sn=d5906f841801913762e849fa6edf59a1&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
