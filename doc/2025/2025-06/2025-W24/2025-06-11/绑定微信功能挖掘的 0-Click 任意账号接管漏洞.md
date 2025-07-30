#  绑定微信功能挖掘的 0-Click 任意账号接管漏洞  
原创 十二  起凡安全   2025-06-11 06:30  
  
**免责声明**  
  
本文中所涉及的技术、思路仅为学习交流，  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，一旦造成后果请自行承担！  
  
**漏洞挖掘过程**  
  
前端功能点如下，点击个人设置，有个绑定微信功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8C4vbODdktE9ibtmQ1oPkc21U0z94ItAibgIT4EzjRnwic76qf55hXuFCA/640?wx_fmt=png&from=appmsg "")  
  
这里开启抓包，刷新一下页面，发现如下数据包，  
此数据包根据用户id值生成一个绑定微信到此账号的链接，id值是不可遍历的，但是我们可以从其他地方获取其他账号的id值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8mpFCT19vlgZFEtcvE0VdzOtibV54zYa5OjtD0GJ24iaickDwEhrWYvbLA/640?wx_fmt=png&from=appmsg "")  
  
找到了一个ai题库功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8AXlYoRkzL2Z43DfbwFiaOGcmBUQpnOvyFRZ38QtgMufyW4Vevk8IHMw/640?wx_fmt=png&from=appmsg "")  
  
权限管理功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64kCao07Va9vqucO6S2v78YdmPPcgZxgjKZH9GgfmfoJaiceZnw2x9zHIqWmULCnHMKdLexYicibM7JIw/640?wx_fmt=png&from=appmsg "")  
  
新建题库功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8F5dzk5p3e24NRLRDAZcxGs0wVVc0BXPZJ492aiaibSdZticIToA8uAcRw/640?wx_fmt=png&from=appmsg "")  
  
开启抓包，点击显示全部教学负责人  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d87IWsI69ib35uRcRTH7x8Fq9JAgVW8LWBm6zJ1MbNOtPJrYiaHyzqUJrg/640?wx_fmt=png&from=appmsg "")  
  
返回了teacherId，拿这个账号测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8nUNTse6Mic3fhHL5GNbc5bCqoHnHtWlD8bYR4qD1KLvlrKDFQ5ibbaAw/640?wx_fmt=png&from=appmsg "")  
  
在一  
开始数据包替换  
id，返回了链接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8r4nAsQgLAHLl29OdkgiagOXsqwIOrltEiarvn0rUevMOehhLqKjoFiawA/640?wx_fmt=png&from=appmsg "")  
  
打开访问，然后拿自己微信扫一扫提示微信号绑定成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8nBbgDtzRjL0Z05FA63gkTVmq4iaY04V9cNILxXRl7Vb4v2gk0KRcb0Q/640?wx_fmt=png&from=appmsg "")  
  
这里先清除下浏览器缓存，然后拿这个微信扫码登录，成功登录账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8nKshVribVm6BAAITh2LItYO0r1iauKlYM5fyR8dNWe0hQiccd42zib2hQg/640?wx_fmt=png&from=appmsg "")  
  
虽然上面获取teacherID需要高权限的教师账号才能访问，但是在学生账号下仍有很多方式获取老师的id，任何老师发布的信息、课表等功能均可以获取，例如下面功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8alTtlJOH6CnrPbqIArK5fXgeyIGnqq9Zbx5Ch9cIPPoFIzibsSOCMLg/640?wx_fmt=png&from=appmsg "")  
  
开启抓包，点击功能点，数据包如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8iasjP2H9xaYcvicMAVFJSpbsYXCVY9P8x7YI5OlibIYsEzcZkbxOZP3ibA/640?wx_fmt=png&from=appmsg "")  
  
账号下面还有一个绑定钉钉功能，也存在同样的漏洞  
  
freebuff帮会限时优惠  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8QLaSMVg17U7DrKTvlGop3oMaic2UM1g2UQoYKIIugBrtTibb9Be3Y5Pg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d853pIPpAIDCSGmdQiah8nbOFr0328S9eIC8LP5KnUaWqgicFvxv3eVK8Q/640?wx_fmt=png&from=appmsg "")  
  
  
