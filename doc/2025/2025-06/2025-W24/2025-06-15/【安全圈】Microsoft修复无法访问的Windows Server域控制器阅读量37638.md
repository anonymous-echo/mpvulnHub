> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070183&idx=3&sn=ae6fc812748c1b2de669b41ea15f0631

#  【安全圈】Microsoft修复无法访问的Windows Server域控制器阅读量37638  
 安全圈   2025-06-15 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj4nnvbWD5NSYhCmhsbZvQEKiaXQ62ZziacZhQ996e9mrBojiayzMJyRnIp6yW7KpkoZe7bYkRyDoNmg/640?wx_fmt=png&from=appmsg "")  
  
Microsoft 解决了一个已知问题，该问题导致某些 Windows Server 2025 域控制器在重启后无法访问并触发应用程序或服务故障。  
  
正如 Redmond 在 4 月份承认该错误时所解释的那样，在重新启动后加载标准防火墙配置文件而不是域防火墙配置文件的服务器将无法正确管理网络流量。  
  
由于此问题，在受影响的域控制器服务器或远程设备上运行的服务和应用程序可能会失败或无法访问同一网络上的端点和服务器。  
  
“Windows Server 2025 域控制器（例如托管 Active Directory 域控制器角色的服务器）可能无法在重启后正确管理网络流量，”Microsoft 表示。  
  
“因此，Windows Server 2025 域控制器可能无法在域网络上访问，或者无法通过端口和协议访问，否则域防火墙配置文件应阻止这些端口和协议。”  
  
本周，该公司在 2025 年 6 月补丁星期二期间发布的 KB5060842 Windows 安全更新中解决了这一已知问题。  
  
无法立即安装本月更新以缓解 bug 的管理员还可以应用临时解决方法，要求他们使用 PowerShell 命令在受影响的服务器上手动重启网络适配器。
```
Restart-NetAdapter *
```

  
  
但是，请务必注意，他们必须在每次重新启动后重新启动它，直到安装 KB5060842 更新，因为每当重新启动受影响的域控制器时，此已知问题都会自动触发。  
  
周二，Microsoft 还修复了另一个已知问题，该问题阻止某些 Windows 用户在安装 2025 年 4 月KB5055523安全更新后使用 Windows Hello 登录其帐户。  
  
4 月，该公司解决了另一个 KB5055523 问题，该问题在使用 Kerberos PKINIT 预身份验证安全协议的系统上启用 Credential Guard 时导致身份验证问题。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】网信办加强数据安全执法，两家违法企业被罚](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070172&idx=1&sn=09d28f84a627fb974e6685c2185eaa5d&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软修复9.3分高危漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070172&idx=2&sn=338cac5913731b091a4e71b214daf70f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】T-Mobile否认6400万用户数据遭黑客窃取事件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070172&idx=3&sn=5d40850d190c39df263227c96a280388&scene=21#wechat_redirect)  
  
  
  
[【安全圈】小区门禁成摇钱树，个人信息被明码标价！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070159&idx=1&sn=b65f406b778af2004ef61b00dab32ccc&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
