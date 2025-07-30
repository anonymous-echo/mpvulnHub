#  SSRF 之 Azure Digital Twins Explorer   
原创 玲珑安全官方  芳华绝代安全团队   2024-07-09 20:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1AoMVy0KnkqEMU3uEJcVqvr4Qicict0PZaDVUSfyyYDiauwQTMXZ4S6akHCfmKrS3V2gmUv8FvNxyEm3HZaianjyoQ/640?wx_fmt=jpeg "")  
  
正文Azure Digital Twins 是一个微软下的平台服务，允许开发者创建和运行数字孪生模型，这些模型能够反映物理世界中的实体及其关系，通过这些模型可以进行监控、分析和预测等操作。  
  
1、进入主页面，创建一项新的数字孪生服务：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsV7I6ZOnIFUebrc7RHoqicsbdbfnWK48Ury4yr4wcJY3l8PQvhXG08Krw/640?wx_fmt=png&from=appmsg "")  
  
2、打开 Azure 数字孪生资源管理器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVmkD4gxJg3ibGoUyIWOy8aFhDKqGKibxHabiafQU0lT1RYdk4BgDp2jGqg/640?wx_fmt=png&from=appmsg "")  
  
3、点击3D场景按钮：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVDH2ZZ8WbNwUicH38JUy2En0secoyKgI4ptRedYtr7WnOict8UZQEQZZg/640?wx_fmt=png&from=appmsg "")  
  
4、此时，存在一请求包如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVbtR8yibP7ezU9hIqAH71Xiaco0SuPv8pjv6MuW505keLAvmdCe9Cx1Gw/640?wx_fmt=png&from=appmsg "")  
  
可以看到名为  
X-Blob-Host 的自定义  
标头被设置为未定义。  
  
5、对应的  
返回包如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVRZzvAZHa4WP1wWG0LIQNUhM4TVvQa4E8NPFDX4AM2Yxu6vxj8sRcBA/640?wx_fmt=png&from=appmsg "")  
  
由于内部服务器错误 500 ，暴露了应用程序的各种依赖项和文件。  
  
6、出于特殊性，修改X-Blob-Host  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVfXRoW7w76zfePoNqIic4aFGbA4M65QxYDibOqQOUQGf46PUkmC1pOkow/640?wx_fmt=png&from=appmsg "")  
  
返回包如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVy3MAKShG0D2qHhlLG190EYm40KrYMVnyCo4ELlGfGQC6tZrG5KLKHw/640?wx_fmt=png&from=appmsg "")  
  
可以看到，我们提供了一个 blob，  
由于后端  
代码检测，导致服务器的请求(getaddrinfo) 错误。  
  
7、在 Github 中检索与数字孪生服务相关的各种文件后，发现一个BlobAdapter.ts文件中似乎存在类似功能，关键代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVoicYp6YBqsCQEoeBtQ57S0RP1VQ3auuIGWUV1rriaf9xhQsxWqx0IOag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVicYv1NCwdhpAkdNcVbj3gvialibzRy1x35b9uOg7G86u8mAglQT793Bpw/640?wx_fmt=png&from=appmsg "")  
  
解读：  
blobHostUrl设置为请求标头中设置的内容（即req.headers['x-blob-ho  
st']）；  
后端验证BlobHostUrlObject标头是否以blob.core.windows.net后缀结尾  
  
由于blobHostUrl可控，因此可构造参数内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVXv8K4Ey22gmMqHaHEcA36A2NMrwX1UufU8VAGotphngWibs8VKH2NiaA/640?wx_fmt=png&from=appmsg "")  
  
其中， | 用于绕过。  
  
响应包及Collaborator如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVHlSrLWvDJic6pNZiaC0hOKFboG9gj1EmYuUN5cnR1FocpfkX8QfGjpGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqSUPgeJYicYLaety1lwNbsVr5QWpn16bQ0MvuYAK6XPicT5picrwyYe5vbSvSGnkLvto4r4OhRiceINQ/640?wx_fmt=png&from=appmsg "")  
  
原文出处：  
https://orca.security/resources/blog/ssrf-vulnerabilities-azure-digital-twins/  
  
SRC漏洞挖掘培训  
  
[玲珑安全第三期如约而至](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493447&idx=1&sn=04e4dfd799d0f22f5adfb1a50032d221&chksm=ebeb05ffdc9c8ce9a3d2916634a4fe3480685bf599150c2e128e20faeae4d2ddd0f12f96b630&scene=21#wechat_redirect)  
  
  
[第二期玲珑安全培训班来啦！](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247491250&idx=1&sn=0a1a522f09c42654a3eb2f314dfedffa&chksm=ebe8fc0adc9f751c60b0fa5c4c15bbc7947de1b50cbb8ecae11b51882a12612323d761e66f1a&scene=21#wechat_redirect)  
  
  
[玲珑安全第一期SRC培训班即将开课！](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247486139&idx=1&sn=11eb92b27684e41a86d26673ec4747f1&chksm=ebe8e803dc9f6115e18384bd62789bf5c5d1ad7de522faf92ebb52893a8cef4631a0f1459112&scene=21#wechat_redirect)  
  
  
往期漏洞分享  
  
[1000美元：重定向的故事](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493667&idx=1&sn=2683402e747a6f52ac93832b72d241a3&chksm=ebeb0a9bdc9c838de2d8f05ba64fb39913c0b4d9921d3145a261ecaee229da35831b7f589b59&scene=21#wechat_redirect)  
  
  
[XSS之绕过HttpOnly实现帐户接管](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493090&idx=1&sn=1ba61d61aec079462e39b136f244f992&chksm=ebeb075adc9c8e4c3c1408e17621b301baf0e48ca9abf79cfba6e1185403adf1d888a3672f1e&scene=21#wechat_redirect)  
  
  
[sql server注入实现RCE](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247492137&idx=1&sn=20e7b1302cbd7894890170c73a9c246d&chksm=ebeb0091dc9c89878ce30f08ae2ca6140e8a77108f8fc5fa9e770478a804f1ba26a49159b50b&scene=21#wechat_redirect)  
  
  
[一个基于 BigQuery 的 SQL 注入挖掘案例](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247484243&idx=1&sn=86d123e40ca61e00e3dba898ee2e35ab&chksm=ebe8e1ebdc9f68fd6b1326fbcbf7ea368c1891143763a3fdfbae62e6d670d2c8267c88d15546&scene=21#wechat_redirect)  
  
  
玲珑安全B站免费公开课  
  
https://space.bilibili.com/602205041  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpVjiaTUMYPLzFcLHPRmjJaYgicYcibBOoTyko1d5gcfhxlu6BMmSFKeQMeqsda7jd3yEiaCekfJjrQXg/640?wx_fmt=png&from=appmsg "")  
  
  
