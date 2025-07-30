#  N/A｜Showdoc 远程代码执行漏洞   
alicy  信安百科   2024-05-30 18:27  
  
**0x00 前言**  
  
  
ShowDoc是一个非常适合IT团队的在线API文档、技术文档工具。通过showdoc，你可以方便地使用markdown语法来书写出美观的API文档、数据字典文档、技术文档、在线excel文档等。  
可以很方便地进行项目文档的权限管理和团队协作，也可以分享文档出去给朋友查看。  
  
  
ShowDoc还支持多平台客户端，有win客户端、mac客户端、ios、android等，更方便跨平台使用。目前超过100000+的互联网团队正在使用showdoc，包括知名公司内部的一些团队，比如腾讯、华为、百度、京东、字节跳动、顺丰等等。  
  
  
  
**0x01 漏洞描述**  
  
  
攻击者通过SQL注入漏洞获取到token进入后台。进入后台后可结合反序列化漏洞，写入WebShell，从而获取服务器权限。  
  
  
  
**0x02 CVE编号**  
  
****  
无  
  
  
  
**0x03 影响版本**  
  
  
Showdoc < 3.2.5  
  
  
  
**0x04 漏洞详情**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Whm7t4Je6uoNSDfC3PtZNeaaUZGLWk0WO7KHBrDSVgyTibX2SFmOBdToasBmUmgOUAOo76xgjUYoLCwiciaVTENqQ/640?wx_fmt=png&from=appmsg "")  
  
(来源于网络)  
  
  
  
**0x05 参考链接**  
  
  
https://github.com/star7th/showdoc  
  
  
https://www.showdoc.com.cn/help/13733  
  
  
  
  
推荐阅读：  
  
  
[CVE-2024-32399｜RaidenMAILD Mail Server路径遍历漏洞（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485273&idx=1&sn=a82529b85eefa1d75072e8232300c89d&chksm=cea96e80f9dee79628ca2241d263499ea7ac27e121407aec485efe779f09d07842ea95f2f0c7&scene=21#wechat_redirect)  
  
  
  
[N/A｜Jeecg commonController 文件上传漏洞（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485251&idx=3&sn=5f20e1d3e3fb8091bb9f2e6a2c8df503&chksm=cea96e9af9dee78cb7ba6f22b45c8c4180459199f16c2697226fdef115ae73582579c7e26195&scene=21#wechat_redirect)  
  
  
  
[N/A｜禅道项目管理系统身份认证绕过漏洞（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485251&idx=1&sn=7598223ae3b4b591ace83cc8e1843488&chksm=cea96e9af9dee78c225ddc1b1d4fada644e572d2bafca55274714385f1cd0d227f8dbb64d26e&scene=21#wechat_redirect)  
  
  
  
  
  
Ps：国内外安全热点分享，欢迎大家分享、转载，请保证文章的完整性。文章中出现敏感信息和侵权内容，请联系作者删除信息。信息安全任重道远，感谢您的支持![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6urTIficI8UhQibwpYWx4ic7Bk40AJlXrgx3icofWCbd5cbJFheld132R8exvlHnicn0AUjHLmVok4wV9qA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
！！！  
  
  
**本公众号的文章及工具仅提供学习参考，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用者本人负责,本公众号及文章作者不为此承担任何责任。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6uqQ24S6worK6npevNP8p1uPc9jQeMAib2iaibBnibOzFaIbD0KlvsEtUAmL3xdbJJnWk74Y1KfBcIazzw/640?wx_fmt=png "")  
  
  
