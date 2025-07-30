#  【安全圈】Cox 存在API 身份验证绕过漏洞，影响数百万台调制解调器   
 安全圈   2024-06-04 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，Cox Communications修复了一个授权绕过漏洞，该漏洞允许远程攻击者滥用暴露的后端api来重置Cox调制解调器的设置并窃取客户的敏感个人信息。据悉，该漏洞影响到了数百万Cox提供的调制调节器。  
  
Cox是美国最大的私人宽带公司，通过光纤网络为30多个州的近700万家庭和企业提供互联网、电视和电话服务。  
  
此次的 Cox安全漏洞是由赏金猎人Sam Curry发现的。他发现一旦威胁行为者成功利用该漏洞，就能够获取到与ISP技术支持类似的一组权限。  
  
攻击者可以利用这一访问权限，通过存在漏洞的 Cox API 访问数百万台 Cox 设备，覆盖配置设置并在设备上执行命令。  
  
举例来说，通过利用这个身份验证绕过漏洞，恶意行为者可以通过暴露的 API，使用 Cox 客户的姓名、电话号码、电子邮件地址或账号查找他们并窃取他们的个人身份信息（PII），包括 MAC 地址、电子邮件、电话号码和地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaCoIBpFYqLnmNWAe0FMU8FHAeOa4ogYzU1d63vhAxt4r5oGBesLiajUw3KpyuiaB7q3S34xicsqmmlg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
不仅如此，攻击者还可以通过查询在前一攻击阶段窃取的硬件 MAC 地址，收集连接设备的 Wi-Fi 密码和其他信息。继而执行未经授权的命令、修改设备设置并控制受害者的账户。  
  
库里表示：这一系列漏洞也展示了一种方法。在不具备任何先决条件的情况下，由外部攻击者执行命令并修改数百万调制解调器的设置，可访问任何企业客户的 PII，并获得与 ISP 支持团队基本相同的权限。  
  
目前已有 700 多个公开的 API，其中许多提供了管理功能，如查询调制解调器的连接设备。每个 API 都存在相同的权限问题，重复重放 HTTP 请求将允许攻击者运行未经授权的命令。  
  
不过，该公司在Curry 报告后的 6 小时内就立即关闭了暴露的 API 调用，并在第二天修补了漏洞。  
  
作为后续安全审查的一部分，Cox 方面还调查了这一攻击向量在被报告之前是否曾被利用过，但截至目前并未发现被滥用的证据。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaJcv5JoQzOHJiav9GjpKPt2eIGU6V1otxl5B7MeHUpmJGw2eRibXX2Xia9OYcqDyRXE1ibcyyrDAZJnA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】国家安全机关破获重大间谍案 涉密岗位人员被MI6利诱策反](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061096&idx=1&sn=3e5967d4fd7d9710e93eddf0cdecf41e&chksm=f36e11e8c41998fe1dcbfb2238c770919bef35172f76ee92b91d18c5b43e4194cdaa390575e8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaCoIBpFYqLnmNWAe0FMU8FbEibeeGfcHjPpaLrGqSHOsDbrMYVR2V3ZoBMibtvXBa4CJgWpB64rU2w/640?wx_fmt=jpeg "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=4&sn=f2d8dc93a6155a2a92a8db3148b35d5b&chksm=f36e1140c4199856cfdf7f6fe9794fdcf8c26069bf14ff1852b6b70a22ccbb9c5ea601a621df&scene=21#wechat_redirect)  
[【安全圈】卡巴斯基发布免费工具扫描 Linux 中已知威胁](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061096&idx=2&sn=e541f58930f0a0d628d67d0928d78f34&chksm=f36e11e8c41998fe49a48f9432232207804a0eec00f85864e2f8c57c58a3c354ae42d792c4e7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaJcv5JoQzOHJiav9GjpKPt2jgeNfwIrxMFib4qPbYCV5UcbxWJL6ywla25jIRibfVPGnsZTibvheETBw/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】59% 公共部门的应用程序长期存在安全漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061096&idx=3&sn=157b0ddf2ea750aeeaff6fe88cc84f0d&chksm=f36e11e8c41998fe83db1c6994cf73d3d4f1d3cc4459af0d5c463741cf3de0b19e88e7cce076&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaCoIBpFYqLnmNWAe0FMU8Fq4ryLibVzLRgqvxPHG8IkKv4UAqTSRSUmkC4Riasic6Chek8sS4gOgMYw/640?wx_fmt=jpeg "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=4&sn=f2d8dc93a6155a2a92a8db3148b35d5b&chksm=f36e1140c4199856cfdf7f6fe9794fdcf8c26069bf14ff1852b6b70a22ccbb9c5ea601a621df&scene=21#wechat_redirect)  
[【安全圈】一天 300 台设备受害，僵尸网络 CatDDoS 向思科 / 华为等发起攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061096&idx=4&sn=4c40f8ea670a8a9e06a0d0cb72ee9b4a&chksm=f36e11e8c41998fe82297ab89688299b97560ce44590b63a6bf09f624419221142397086f688&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
