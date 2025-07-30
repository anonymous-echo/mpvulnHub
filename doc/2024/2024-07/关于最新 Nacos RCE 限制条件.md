#  关于最新 Nacos RCE 限制条件   
原创 酒零  NOVASEC   2024-07-15 21:47  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZDxicuqPkFfjdG2kcyzCXrXfiaOqkg7qkk63ibvpfNVSajOwXV5dg0xhupKGhQ3lugDyy0ehGIazYyEw/640?wx_fmt=png "")  
  
  
  
  
  
**△△△点击上方“蓝字”关注我****们了解更多精彩**  
  
  
  
  
  
**0x00 简介**  
  
  
非常开心  
还  
以为能吃上麦当劳了。  
研究一番，发现吃不上了。  
  
  
  
**0x01 限制条件说明**  
  
****```
1、主程序版本无限制:  
  常见的1.X-2.X基本都是OK
  
2、认证没有太多限制: 
  基本都是弱口令和权限绕过

3、运行方式限制RCE方式 
  公开POC中调用的derby数据库属于默认独立启动才会使用
  生产环境下都是mysql数据库,mysql没有这个函数.
```  
  
  
  
  
**0x02 总结**  
  
  
希望大家遵守【网络安全法  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icZfUh6Tsbv0xAFjs5qQlsFCCmymOS3Vq8v6OSKDP0pw3aoCD4OTqojr5NMysBOcoMehddw6JUqYXVuurThNLsQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
**0x99 免责声明**  
  
  
在学习本文技术或工具使用前，请您务必审慎阅读、充分理解各条款内容。  
  
  
1、本团队分享的任何类型技术、工具文章等文章仅面向合法授权的企业安全建设行为与个人学习行为，严禁任何组织或个人使用本团队技术或工具进行非法活动。  
  
  
2、在使用本文相关工具及技术进行测试时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。如您仅需要测试技术或工具的可行性，建议请自行搭建靶机环境，请勿对非授权目标进行扫描。  
  
  
3、如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
  
  
4、本团队目前未发起任何对外公开培训项目和其他对外收费项目，严禁任何组织或个人使用本团队名义进行非法盈利。  
  
  
5、本团队所有分享工具及技术文章，严禁不经过授权的公开分享。  
  
  
如果发现上述禁止行为，我们将保留追究您法律责任的权利，并由您自身承担由禁止行为造成的任何后果。  
  
  
  
END  
  
  
  
如您有任何  
投稿、  
问题、需求、建议  
  
请  
NOVASEC公众号  
后台  
留言！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCP3AeicSCQAYIOvxVDSRUxpiadmBKZ8gtggx02BmG1WwCqoM23l72qV8AiabXSRKjGmk8S1HS1nTjXw/640?wx_fmt=png "")  
  
或添  
加 NOVASEC   
联系人  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/toroKEibicmZD7m4f7uBkNfCG8BjypNEukN0Ht6Ha0XsryrmS5PAmaVeyzb3JzsH5ibx6DmpHq9e8agwMkccrwNSQ/640?wx_fmt=jpeg "微信图片_20201214143605.jpg")  
  
  
感谢您对我们的支持、点赞和关注  
  
加入我们与萌新一起成长吧！  
  
  
**本团队任何技术及文件仅用于学习分享，请勿用于任何违法活动，感谢大家的支持！！**  
  
  
  
   
  
