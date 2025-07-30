> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535507&idx=1&sn=aa8fe2a260fb9665fcc45a09e0579751

#  【漏洞预警】：Redis hyperloglog 远程代码执行漏洞  
原创 52  易云安全应急响应中心   2025-07-11 07:55  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fDHeGBHFP0hPMGraOX89rxSCkNb6CfyJllPlVyM0E8HZPeqk0eGuE3yvIAhW0uWm6GPKUNazNEWBKIjicIpS3Og/640 "")  
  
点击上方  
蓝字  
关注我们  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gMiabmiaticAtTED79NtWVQEmRPshZZHiczXbu6ExFb8dFVGickw8GpAJCkNsKIVaiaQsyPjYVXrvAKlpYSH00f8E5BQ/640?wx_fmt=png&from=appmsg "")  
  
01  
  
漏洞描述  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
近日，易云科技监测到  
Redis hyperloglog 命令远程代码执行漏洞。  
  
Redis（Remote Dictionary Server） 是一个开源的内存键值数据库（In-Memory Key-Value Store），同时支持持久化到磁盘。它以高性能、低延迟、数据结构丰富著称，常被用作缓存、消息队列和实时数据处理引擎。  
  
1.漏洞编号  
：  
QVD-2025-26361、CVE-2025-32023  
  
2.发现时间：2025-7-11  
  
3.漏洞类型：远程代码执行  
  
4.漏洞等级：高危  
  
5.POC/EXP：已公开  
  
6.在野利用：否                                                                                      
  
02  
  
漏洞危害  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
经过身份验证的攻击者可通过构造特定的恶意字符串，在 HyperLogLog 操作中触发堆栈或堆内存的越界写入。由于内存破坏可能被进一步利用，此漏洞最终可能导致远程代码执行（RCE）  
。  
  
03  
  
受影响版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
该漏洞  
影响以下版本的 Redis 产品：                                                         
  
2.8<=version<6.2.19；  
  
7.2.0<=version<7.2.10；  
  
7.4.0<=version<7.4.5；  
  
8.0.0<=version<8.0.3 。                                                                
  
04  
  
处置建议  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
针对此漏洞,Redis官方已经发布了漏洞修复版本,请立即更新至安全版本。               
  
Redis 8.0.3 或更高版本；  
  
Redis 7.4.5 或更高版本；  
  
Redis 7.2.10 或更高版本；  
  
Redis 6.2.19 或更高版本。  
  
下载地址：  

```
https://github.com/redis/redis/releases
```

  
临时缓解措施：  
- 在不影响业务的情况下，通过使用ACL来限制HLL命令，阻止用户执行hyperloglog操作；  
  
- 确保Redis配置了身份验证和访问控制。                                                       
  
  
  
05  
  
参考链接  
  

```
https://mp.weixin.qq.com/s/xqQlZugJsPuypmt07Udk2Q         
```

  
  
  
END  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**淮安易云科技有限公司-****网络安全部**  
  
我们致力于保障客户的网络安全，监控事件并采取适当措施，设计和实施安全策略，维护设备和软件，进行漏洞扫描和安全审计,团队协调处理网络攻击、数据泄露等安全事故，并负责安全服务项目实施，包括风险评估、渗透测试、安全扫描、安全加固、应急响应、攻防演练、安全培训等服务，确保客户在网络空间中的安全。  
  
**易云安全应急响应中心**  
  
专业的信息安全团队，给你最安全的保障。定期推送  
漏洞预警、技术分享文章和网络安全知识，让各位了解学习安全知识，普及安全知识、提高安全意识。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NuIcic2jibgNJzwoZYCo6ThfOoeX410mwuDxnOnv5za18VZJ7ib30pic2NSNnicziaONicvs1C9yMDr6zV40ADD9yPP7Q/640 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rSGIepMCCX1b954EWhfGX7OEmRIa71iba6JEFiaLvMfVbc2kibDbjiaqtzrAiaXV9URkwkIzNHfycOb4XguqfU5ZyCw/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gMiabmiaticAtSia0prnfkWIj7vlIkbFPGibN2sUrBbqFSpgHDHhz9s0ic6smsEy0Dae8bnOUPibYNuuj4gwOyqjiac9ow/640?wx_fmt=jpeg&from=appmsg "")  
  
扫码查看更多信息  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/w0ZFaKZYbTQtQwjxiaot5eaGSRHfWOPYRtV99K39iaib3oo21ugsg8QBJWKpcs90xheFNMR95qcK9wHRLqNnMqfOQ/640 "")  
  
  
往期推荐  
  
  
  
[境外黑客瞄准校园广播！“声波毒蛊” 被截获，国家安全部紧急提醒](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535470&idx=1&sn=1e457309776e6bf5dd162681fe606a63&scene=21#wechat_redirect)  
  
  
[七国恶意网址 / IP 被揪出，国家通报警示！](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535470&idx=3&sn=73205f2dbc6b3b4ca4854d7b88a5bcf2&scene=21#wechat_redirect)  
  
  
[安利｜SQL 注入克星！Burp Suite 这款插件必试](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247535470&idx=4&sn=91758ef456aa40208be8b9bdd287ddc5&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaic181R2RnYicpic6GbdiazMpqiaIrCaa2fbjKHtn8kiayKGGBeW0icqgpfzNqmibShxqsn2DMDggpaxnKjrY1sCWZXWng/640 "")  
  
转发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItKicuUNQ9EMVAsW4tKUASR3dbCFrBib4ibY05IeDzhxf9b1KMxjzLaukAYt0NfYLchE5eibmaSHibiamfT9wDQibytww/640 "")  
  
收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jwUk1NOJTytvIJd6VYGIIp4cA0qNKtMv7tAziatxhK4whicjTxAPklWUEfjejWvRbEbJjKDoRhZpUaPaEibpFYbcQ/640 "")  
  
点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/K2CMDET8V6nLGsmoNxVfZytJuZzowIia6LuVg70JTa2jGiaozMwyvhG9eKOKVa5rzaj1QOgfPm4a2lsEJ7GN7zCQ/640 "")  
  
在看  
  
