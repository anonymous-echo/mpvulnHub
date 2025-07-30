#  开源堡垒机teleport任意用户登录漏洞审计   
print("")  渗透测试网络安全   2023-04-15 16:12  
  
声明：该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。0X00 任意用户登录分析  
拿到更新包进行对比首先更新包更新了两个文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ewSxvszRhM4UU95wvgaUY1WBuRznG6RJCDicfMAKMoMjul8E2mGplHqOAbWiaWNQicRroDPq3DWGso7gqxd1mjnYQ/640?wx_fmt=png "")  
  
对比auth.py  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ewSxvszRhM4UU95wvgaUY1WBuRznG6RJ4CzEdYKYuibHcz8gk5fapy73Aaga7e3djs8BhGUsiazB0ETTO4rF9G7Q/640?wx_fmt=png "")  
  
两个地方。一个是elif 改成了if 然后是检测了密码是否存在。那么跟进去代码看看login 的逻辑![](https://mmbiz.qpic.cn/mmbiz_png/ewSxvszRhM4UU95wvgaUY1WBuRznG6RJicicGiav5bguIPbIfOCOZV5MelkRnAXdObbVzNIOK1YrAJNWVFo01J4xQ/640?wx_fmt=png "")  
  
只要password 为None 那么就可以跳过密码验证。  
让p  
assword 为None 就直接用 json.dumps![](https://mmbiz.qpic.cn/mmbiz_png/ewSxvszRhM4UU95wvgaUY1WBuRznG6RJ7mYNjELCjHF9lhfLjducT3gTVZcsF4iayS0az2lEXojrDtW6ffqw7icg/640?wx_fmt=png "")  
  
pyaload 如下:  
  
```
```  
  
0X01 任意文件读取  
![](https://mmbiz.qpic.cn/mmbiz_png/ewSxvszRhM4UU95wvgaUY1WBuRznG6RJF8IpXfucrJYPTGF0eJMcK0aCfD1l7fQiaGOgVPPvdHUaiaRomBeZBVAQ/640?wx_fmt=png "")  
  
payload如下：  
```
```  
  
作者：print("")  
  
原文地址：https://www.o2oxy.cn/4132.html  
  
**关 注 有 礼**  
  
  
  
关注本公众号回复“  
718619  
”  
  
可以免费领取全套网络安全学习教程，安全靶场、面试指南、安全沙龙PPT、代码安全、火眼安全系统等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
 还在等什么？赶紧点击下方名片关注学习吧！  
  
  
  
  
