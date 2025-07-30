#  kangle 虚拟面板存在前台XSS漏洞   
原创 星悦  星悦安全   2025-04-22 08:06  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 过程  
  
已知在Linux 下 可构造带特殊符号文件名的文件  
  
> '<xxx>xxxx<xxx>' 即可写文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGSetNSznROh7dia7cUaWs8icicO8S0K0wibaCgiaBmbXJBAZbtb4lAv9o36xVr1ZdBhLO0Z0Jq8Fu7ibA/640?wx_fmt=png&from=appmsg "")  
  
需在   
kangle 面板查看其目录后可触发.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGSetNSznROh7dia7cUaWs8Qu2trfAk7WMTRBxwf2YDmU7NaveX3r0NY2Wp4PA33jQ9VWOk5vjy6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGSetNSznROh7dia7cUaWs8qfwkch3giaf3TxWGXSg5XSwzNr6x704knuI7KOibyD50zeOE2znxNzYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eGSetNSznROh7dia7cUaWs8wHmLhUGPODqV6Y0X8icHayroybfsV5AYwcrIic7yXUGlyBsSnLhJDESw/640?wx_fmt=png&from=appmsg "")  
  
这里不给出Payload，  
有兴趣的可自行测试.  
## 0x02 关注公众号  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
