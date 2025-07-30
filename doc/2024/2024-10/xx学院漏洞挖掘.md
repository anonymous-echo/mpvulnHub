#  xx学院漏洞挖掘   
爱喝酒烫头的曹操  秘地安全实验室   2024-10-07 22:10  
  
**免责声明**  
  
       
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，  
安全性自测  
，如有侵权请联系删除。  
  
  
**0****1**  
  
**0x01漏洞描述**  
```
```  
```
本文章主要来资产所在网段：互联网。记录某中医药大学xx学院的完整渗透过程
从信息泄露开始循序渐进的进行挖掘，中途发现多个此站点存在的漏洞，包括
（未授权访问、水平越权以及存储型xss等）。
```  
  
**02**  
  
**0x02 漏洞复现**  
  
```
漏洞URL：
http://xx.xx.com/index
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnNK5HC64hibL7g7LzW870CwhfiaZdMkSadHMOcgcTkRhVvGqQVVdjb7yg/640?wx_fmt=png&from=appmsg "")  
  
  
```
漏洞点一：未授权
 
添加实训课程： /module/experiment/index/addexperiment/?id=5
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnQ5z6hSpEx8RrCGFHUYCb15m6icia5DiatIhMQ874cTw8Hd9BcrXpw7aWA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQngP8v7jDZlYoc0YqvSpEz8BgiaLf3W3acRr8N57vufgKIh84AicL8YdBQ/640?wx_fmt=png&from=appmsg "")  
  
点击确定。  
```
查看学生：/module/experiment/index/groupstudent/?id=50
存在手机号，如若遇到不法分子可使用电话号码进行电信诈骗
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnlU8icYeUC9e640jEj6cytJc8TgWGw6KZERyliaHz7JeUx9zegMsrn8zg/640?wx_fmt=png&from=appmsg "")  
```
未授权下载：module/experiment/index/exportstudent
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnDoUohMicFCCYgicVo2fTzJwujF8WvVvLNMd9snI1DV3gFyGJNcicbjxFw/640?wx_fmt=png&from=appmsg "")  
  
漏洞点二：两处存储型xss
点击实验报告 进行添加报告
随后点击箭头标记点，填上payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQno0tE0vclib2lXibic9A93pZqR5fBPnx6e5oaSaApRLr9MRKGr8RMdkcKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnGiaYUP179XekNmZyqxu7qtJiaE8tdS3fQQgdMKwHHUPdpbyGWyFibWTMw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnKCSAlG7reVpFQw7lkU7ksica6uEQlraasrdfPBvIVHeWu83OCjxxEVQ/640?wx_fmt=png&from=appmsg "")  
  
点击insert link
随后点击发布   
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnEgwibuFO2tU71tEecH5CHz9dyfcZ99eeaqovZxImfic92lpYSkQk2Xmg/640?wx_fmt=png&from=appmsg "")  
  
随后点击修改进入后成功弹窗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQndGCObKQ9RZdnGDMxpWCJMXibwoheO7JibCslPc9pHpe3IVrniayibu8rog/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
漏洞点三：水平越权
还是进去修改报告页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnhYCZZmr2b8mDtXjhibibhvVz7ibgbhyAKCfvcYFNQel6sJ8CMf7bY2lIg/640?wx_fmt=png&from=appmsg "")  
  
随后更改url中id的参数：我们把id=46改为id=40，然后进行发布  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnUSkjjvQLTg7pnD5uluVEtlCK4rb94B0GVzjfVaRFUtps1LZdnBufoA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnKt6k9icwLIUiariaqARTt5Gxqp84271VKia5JhYS2e23W0HC1V7RjxgEAg/640?wx_fmt=png&from=appmsg "")  
  
点击发布即可把别人的报告发布成自己的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfOKIfJx5JrJAreBkibOdLAQnibX7Wrqlh2Fze1rc354ZackP1ABq1PFN7xYf3R1KaTHkbF5dPE4OiaoQ/640?wx_fmt=png&from=appmsg "")  
  
```
温馨提示：所有漏洞均已进行报送且修复，请勿进行不必要的尝试！
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OV3NwjYeQfPib0tv3CytsEDAkBQzNTSSeYR2zgXUXba4nkfWWJrzw8XCB2BqnQ9MZRG2038CLzZiatdjp5bLAAMQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OV3NwjYeQfPib0tv3CytsEDAkBQzNTSSeOSuxq04gibGzmFEiaJ0892HVNKibiaun9FPpoNDKUsM8qQO9ZRzgCwHcow/640?wx_fmt=png "")  
  
**END**  
  
****  
  
