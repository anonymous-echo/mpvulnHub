#  【安全圈】Cisco 再曝超严重漏洞，黑客可修改管理员密码   
 安全圈   2024-07-18 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，思科公司披露了其智能软件管理器本地版（SSM On-Prem）中的一个关键漏洞，该漏洞允许未经身份验证的远程攻击者更改任何用户的密码，包括管理员用户的密码。这个漏洞被追踪为 CVE-2024-20419，其严重程度评分为 10 分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhEa6M1AIDFKXVZYkvibHolmkkAPfB37l9kuvJwPeIj3M2HPo6EqUv8YiaxAez2icXYq3tZkq3u65IlQ/640?wx_fmt=jpeg&from=appmsg "")  
据悉，该漏洞是由于思科 SSM On-Prem 认证系统中密码更改过程执行不当造成的。  
  
攻击者可以通过向受影响的设备发送特制的 HTTP 请求来利用这个漏洞。成功利用将允许攻击者以受影响用户的权限访问 Web UI 或 API，从而在未经授权的情况下对设备进行管理控制。  
## 受影响的产品  
- 思科 SSM On-Prem  
  
- 思科智能软件管理器卫星版（SSM Satellite）  
  
思科 SSM 卫星版已更名为思科智能软件管理器。对于 7.0 版本之前发布的版本，该产品称为思科 SSM 卫星版。从 7.0 版本开始，它被称为思科 SSM On-Prem。  
## 已修复的软件  
  
思科已发布软件更新来解决此漏洞。修复的版本如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhEa6M1AIDFKXVZYkvibHolmP6iaH2MXozgesuTrlaRGIAPJSuIoW7mmgQ27BnJ4c27QOaRzBSXP23A/640?wx_fmt=jpeg&from=appmsg "")  
  
思科建议所有客户升级到修复版本以降低风险，保护其系统安全。  
  
截至目前，尚未有公开的公告或证据表明此漏洞被恶意利用，思科的产品安全事件响应团队（PSIRT）将继续监控这一情况。  
  
另外，拥有服务合同的客户应通过其常规更新渠道获得安全修复程序，没有服务合同的客户可以联系思科技术援助中心（TAC）以获得必要的更新。  
## 如何检查思科智能软件管理器本地版的版本  
### 访问管理门户  
  
打开一个 Web 浏览器，输入思科 SSM On-Prem 服务器的 IP 地址和端口号。例如，如果 IP 地址是 172.16.0.1，则输入：https://172.16.0.1:8443/admin  
### 登录  
  
使用管理员凭据登录管理门户。  
### 查找系统运行状况部分  
  
登录后，导航到管理门户的“系统运行状况”部分。此部分通常显示的是思科 SSM On-Prem 安装的当前软件发布版本。  
  
参考来源：https://cybersecuritynews.com/cisco-ssm-password-change-vulnerability/  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhEa6M1AIDFKXVZYkvibHolm88vTnxnGCoicib3ycb6YdqCgicYTgsyfduT19ZYSeB11C05MXFy64V60w/640?wx_fmt=jpeg "")  
[【安全圈】四部委所属7家单位利用政务数据违规牟利2.48亿元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062893&idx=1&sn=af5e54f7671fef6c12bb573a19275011&chksm=f36e68edc419e1fbfdd50401994c897ac7a6ea7b5a776a3b8919fc00bf485e6de6459c770e95&scene=21#wechat_redirect)  
   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgO6TceNReqBOevTH1euXx8LtTUOg7THE5ywtJER3yeA9fU7ITO8vDz5SMlmapyNoKUOIloicA0Q2Q/640?wx_fmt=jpeg "")  
[【安全圈】1.1亿用户数据被窃后，AT&T向黑客支付了37万美元赎金](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062893&idx=2&sn=e92b1e27fc304c0f4d6826a4e9b9a94f&chksm=f36e68edc419e1fb8e11f0f5a5a227ae56ce66378ac718bbada4d455b6fb6893ef0e3bff7434&scene=21#wechat_redirect)  
       
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgO6TceNReqBOevTH1euXx8d8cPFtqa2UlZJsicwuoyXxgWY4qibEicnEZG40x8cF8IjhhGPRL8TjvDQ/640?wx_fmt=jpeg "")  
[【安全圈】知名工具Trello被黑客攻击，泄露1500 万用户数据](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062893&idx=3&sn=6105a9b4f5d23562073d578125379361&chksm=f36e68edc419e1fbff78dac9176d1a269bcef817f43f5a1d186795a31ffa8697665dd6059f7b&scene=21#wechat_redirect)  
              
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgO6TceNReqBOevTH1euXx86C7XCzczoaFsiaLU6nrWYd0gQEtYBQLccypSnZonicFfED81KN6ssXicg/640?wx_fmt=other "")  
[【安全圈】新型广告欺诈：“Konfety”利用Google Play应用商店混淆视线](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062893&idx=4&sn=2d39bccc6ea89921198e43977f1673dd&chksm=f36e68edc419e1fb1e2129e04637aca504507aedbb3a6f15c7f70984ccc381c06c38b5494bb3&scene=21#wechat_redirect)  
             
  
  
  
  
  
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
  
