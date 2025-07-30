> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535298&idx=2&sn=ef61c442d5a8cbb8da9894162f54ec2e

#  安利：Tomcat漏洞批量检测工具  
 易云安全应急响应中心   2025-06-23 07:29  
  
点击上方  
蓝字  
  
![](https://mmbiz.qpic.cn/mmbiz_png/l30icYpcXht5lgLVqGT0ySL1kjyG8L69LLKQbTiafNAUzCxs4uSiagA5YiaVQweWrhxBO40f5s13YoIgA2vubbicu2g/640?from=appmsg "")  
  
关注我们  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gMiabmiaticAtQmFib2LEiaRHL2hOQlthybwwP32Xl4jK9yTgnbv9tb9NwePmL1ObdJdtmDMazZRdm7vtibdicW8LLAOQ/640?wx_fmt=png&from=appmsg "")  
  
  
Start  
  
  
  
项目地址：  

```
https://github.com/lizhianyuguangming/TomcatScanPro
```

  
该项目是一款针对 Tomcat 服务的漏洞检测工具，支持利用 CVE-2017-12615 、 CNVD-2020-10487 漏洞、弱口令检测和直接后台部署war包功能，帮助用户高效获取服务器敏感信息。工具支持多目标并发检测，并通过动态线程池提升资源利用率和检测效率。  
  
  
Action  
  
  
  
使用方法也很简单：  
- 首先准备包含URL、用户名和密码的文本文件，分别命名为：urls.txt、user.txt 和 passwd.txt。  
  
- urls.txt 中的格式为：https://127.0.0.1/ 或 https://127.0.0.1/manager/html，脚本会自动判断路径进行检测。  
  
- 在 config.yaml 文件中配置上述文件路径及相关参数。  
  
- 运行脚本后，成功利用漏洞的信息将被记录到 success.txt 文件中。  
  

```
python TomcatScanPro.py
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gMiabmiaticAtQmFib2LEiaRHL2hOQlthybww9xGvcMUoic2VTWONJcbNAcnP9oBQa2sRUBtDmFEYRtiaNK8cib4bWAn4Q/640?wx_fmt=png&from=appmsg "")  
  
文章来源：跟着斯叔唠安全  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Z6T54FrymeRRzLLj5dQyz33akQ5gA81jeKTOsK5R4cEkorEQXugsnJWyv4ubZK19cq6WPibggc5SnOQz3xm66SA/640 "")  
  
  
免责声明  
  
本文素材(包括内容、图片)均来自互联网，仅为传递信息之用。如有侵权，请联系我们删除。  
  
  
END  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**淮安易云科技有限公司-****网络安全部******  
  
我们致力于保障客户的网络安全，监控事件并采取适当措施，设计和实施安全策略，维护设备和软件，进行漏洞扫描和安全审计,团队协调处理网络攻击、数据泄露等安全事故，并负责安全服务项目实施，包括风险评估、渗透测试、安全扫描、安全加固、应急响应、攻防演练、安全培训等服务，确保客户在网络空间中的安全。  
  
**易云安全应急响应中心**  
  
专业的信息安全团队，给你最安全的保障。定期推送  
漏洞预警、技术分享文章和网络安全知识，让各位了解学习安全知识，普及安全知识、提高安全意识。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NuIcic2jibgNJzwoZYCo6ThfOoeX410mwuDxnOnv5za18VZJ7ib30pic2NSNnicziaONicvs1C9yMDr6zV40ADD9yPP7Q/640 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/qae1K3r24EZ0M9qZAia6YicddnOVklo3plxEyjBvMibxXN6KjoUsYcYIvibPwFPTRgsicpuJHMWZlRlDWkqMQcWLBsg/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gMiabmiaticAtSia0prnfkWIj7vlIkbFPGibN2sUrBbqFSpgHDHhz9s0ic6smsEy0Dae8bnOUPibYNuuj4gwOyqjiac9ow/640?wx_fmt=jpeg&from=appmsg "")  
  
扫码获取更多精彩  
  
往期推荐  
  
[紧急预警：二手平台惊现LABUBU连环骗局！](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535272&idx=1&sn=e32d50deff43aca7f3dcfc73ccbdfc83&scene=21#wechat_redirect)  
  
  
[【漏洞预警】：高危警报！微软公司通报多个安全漏洞](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535205&idx=1&sn=79c060ff2a09da91f05ed22d90bb8400&scene=21#wechat_redirect)  
  
  
[0.02秒劫走专家号！警方斩断黑客黄牛“超算抢号”黑产链](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535205&idx=2&sn=de5deece93b393682f194410e4eb08ca&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaic181R2RnYicpic6GbdiazMpqiaIrCaa2fbjKHtn8kiayKGGBeW0icqgpfzNqmibShxqsn2DMDggpaxnKjrY1sCWZXWng/640 "")  
  
转发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItKicuUNQ9EMVAsW4tKUASR3dbCFrBib4ibY05IeDzhxf9b1KMxjzLaukAYt0NfYLchE5eibmaSHibiamfT9wDQibytww/640 "")  
  
收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jwUk1NOJTytvIJd6VYGIIp4cA0qNKtMv7tAziatxhK4whicjTxAPklWUEfjejWvRbEbJjKDoRhZpUaPaEibpFYbcQ/640 "")  
  
点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/K2CMDET8V6nLGsmoNxVfZytJuZzowIia6LuVg70JTa2jGiaozMwyvhG9eKOKVa5rzaj1QOgfPm4a2lsEJ7GN7zCQ/640 "")  
  
在看  
  
