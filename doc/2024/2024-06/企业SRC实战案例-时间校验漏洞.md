#  企业SRC实战案例-时间校验漏洞   
猎洞时刻  猎洞时刻   2024-06-18 22:36  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9evFcNH31Pjh0f83GEqsibSQsGS8uUrBPLU6VJbjw8CTibOgsYYOhqqKpaQHb9BicrJcCOYhZG0tYOg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6mG6TyJornrhz9JticBo3Nx4zhzUFXcggEDw1lkfzMI0KuLp7dW4dDCvbfgAKlLSX3yGmYg0gtXcw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
```
本公众号“猎洞时刻”旨在分享网络安全领域的相关知识，仅限于学习和研究之用。本公众号并不鼓励或支持任何非法活动。
本公众号中提供的所有内容都是基于作者的经验和知识，并仅代表作者个人的观点和意见。这些观点和意见仅供参考，不构成任何形式的承诺或保证。
本公众号不对任何人因使用或依赖本公众号提供的信息、工具或技术所造成的任何损失或伤害负责。
本公众号提供的技术和工具仅限于学习和研究之用，不得用于非法活动。任何非法活动均与本公众号的立场和政策相违背，并将依法承担法律责任。
本公众号不对使用本公众号提供的工具和技术所造成的任何直接或间接损失负责。使用者必须自行承担使用风险，同时对自己的行为负全部责任。
本公众号保留随时修改或补充免责声明的权利，而不需事先通知
```  
  
  
    大家一直都在学时间校验漏洞，但是很多师傅们并没有挖到过这个漏洞，很多师傅都认为app才存在时间校验漏洞，其实微信小程序也会存在这个漏洞，下面看这个简单的案例。  
  
  
先看我目前的时间，时间为8.31 号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0Xj0m6G2Q8SnhUQRfwrRGv0uOTZxzjllMCbavWGZsuP8Wib88dIxYgOwA/640?wx_fmt=png&from=appmsg "")  
  
  
打开一个微信小程序，发现我有一个优惠券，还有4天就过期了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0X1LB6AKpnVnIWft6iaLqUIaiaooicEAC2pakvibHaKvwJh8JImnF674UibrA/640?wx_fmt=png&from=appmsg "")  
  
然后我直接修改手机模拟器的本地时间，修改为前两天。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0XFyFQAfoZU3FgM4kpWUJE0ibLq1QhGgodotJiahqWQicsMzuV76lzF9RicA/640?wx_fmt=png&from=appmsg "")  
  
发现优惠券的过期时间更改了，使用的时间延长了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0XCBtZbZicFHYeFoHTv5UZoPPjoty23472p1pnSgZ9344LFegvB1sJ8DQ/640?wx_fmt=png&from=appmsg "")  
  
这种时间校验型漏洞，可以在优惠券，预约，还有已过期优惠券，已过期物品等方面都可以去使用，直接修改模拟器，或者真机的本地时间，就能进行漏洞测试。  
  
提交到src平台，也成功通过。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0X1dQPkm72d7VUKqWp4qgxljJF0lVbqQQy171SIq5fibyyIwMzhcLMibeg/640?wx_fmt=png&from=appmsg "")  
  
既然一个小程序存在该漏洞，基本上其他小程序也会存在时间校验漏洞，直接通杀刷起来~  
  
# 内部圈子618大促！！！  
  
**我看最近很多师傅都在618大促，那我也来一次，**  
**原价108￥，目前直接打5折，仅需58￥就能永久加入猎洞时刻内部圈子**  
**，并且期限是永久！！！！**  
  
**加入圈子可以获取更多src、cnvd、edu等学习报告和手法！数量有限，仅限三天！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0XbtHYKibHFoKQZ1piauHtERNpdFYaFVusak2zNSIE4tgpeR2euPmJpMWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8QoTthWcfyUibt2NBpMVk0X02R0rh0fF81XC0GxQWrU1ibxWxCuRqy13YDSDPIEZ0H0N1GvZWOW2qg/640?wx_fmt=png&from=appmsg "")  
  
****  
  
  
