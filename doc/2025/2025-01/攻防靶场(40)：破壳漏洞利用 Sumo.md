#  攻防靶场(40)：破壳漏洞利用 Sumo   
原创 罗锦海  OneMoreThink   2025-01-14 16:01  
  
欢迎提出宝贵**建议**  
、欢迎**分享**  
文章、欢迎**关注**  
公众号 OneMoreThink 。  
  
目录  
  
1. 侦查  
  
    1.1 收集目标网络信息：IP地址  
  
    1.2 主动扫描：扫描IP地址段  
  
    1.3 主动扫描：字典扫描  
  
    1.4 主动扫描：漏洞扫描  
  
2. 初始访问  
  
    2.1 利用面向公众的应用  
  
3. 权限提升  
  
    3.1 利用漏洞提权：操作系统内核  
  
靶场下载地址：https://www.vulnhub.com/entry/sumo-1,480/  
## 1. 侦查  
### 1.1 收集目标网络信息：IP地址  
  
靶机启动后，没有提供IP地址。由于Kali和靶机在同一个C段，可以扫描ARP协议获取靶机IP地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkBETIPSDyAFu5ymKIV9ic6Ht8POBdbHQTW7Md3f8T2SAvhzej6Wdv3xA/640?wx_fmt=png&from=appmsg "")  
### 1.2 主动扫描：扫描IP地址段  
  
对靶机进行全端口扫描、服务扫描、版本扫描，发现22/SSH、80/HTTP。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkqZ7AK6EYOMlJMT2xfAuPAzaM7FfzeqSDdSv0M3AhxcwTFj76q9IztQ/640?wx_fmt=png&from=appmsg "")  
### 1.3 主动扫描：字典扫描  
  
扫描网站目录和页面，发现/cgi-bin/目录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkKMS42BcLz6wXdemIMY5CcuER2Y99ibKFlnicnZ5qhwDO3DiaosdLN4dxQ/640?wx_fmt=png&from=appmsg "")  
  
扫描/cgi-bin/目录下的目录和页面，发现test页面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkrOicibdicJ5bicw6AuxkPDs13aTrrFIk6YvGdiasO1DfpJn48qPyq0DfhtA/640?wx_fmt=png&from=appmsg "")  
  
但是/cgi-bin/test页面没啥内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJke2jSPYW6eB4hibIudomZiccpXHwkel8O6PkOJ0M7icroibzKPhDqYNP1GA/640?wx_fmt=png&from=appmsg "")  
### 1.4 主动扫描：漏洞扫描  
  
扫描/cgi-bin/目录下的漏洞，疑似存在shellshock破壳漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkpEFEdlZ3OO0mJTlkAPM6ibdBrfj4eO2d984IkiaPtZTDLbBcu87IdtzA/640?wx_fmt=png&from=appmsg "")  
## 2. 初始访问  
### 2.1 利用面向公众的应用  
  
通过UA头向CGI程序的环境变量注入恶意代码，在CGI程序处理CGI请求时触发执行，确认/cgi-bin/test页面存在破壳漏洞，可以执行任意命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkUcbFdNqicvT33j0AERJicKcnA8zpjhmiaJFBY3YuA1ictPKiaNeibVzffxWg/640?wx_fmt=png&from=appmsg "")  
  
执行反弹shell的命令，**获得www-data用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkuG1S4QZ3HxeQA4QCVsicHdeHXH8WmichjPKlTXAvbJaD3tibRicibLFlZwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkiahAaqwnpice2ibvfB3pKfNv5Pce6LX7nbzHO4FuDHqhGFnHvNIUgnuPA/640?wx_fmt=png&from=appmsg "")  
## 3. 权限提升  
### 3.1 利用漏洞提权：操作系统内核  
  
查看Linux的内核版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkWrwQdETtAjAqI9LJxyS2p89OiatWbtbBibwJnnhQ4k4bCIcMdoJ1ubCg/640?wx_fmt=png&from=appmsg "")  
  
查看Linux的发行版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJk7bBO2niaG4Z6EqkhyMR86E8OJyicLiaDeFCGib36cvm31vCs5rmLCyxERA/640?wx_fmt=png&from=appmsg "")  
  
确认Linux的内核版本和发行版本存在提权漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkWYvSR0go5exiatziaUICxoiadl03OkMtDd5njLRaelzWvoiasNxa5wBlibQ/640?wx_fmt=png&from=appmsg "")  
  
编译EXP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkAddCWeibd7dCMNrN4NgibAfQhAFcckFzEerZ2fCvaux3UdvRcdK9Co8g/640?wx_fmt=png&from=appmsg "")  
  
将EXP上传到目标机器，并赋予执行权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkePJ4UBFfGOgD5U5YmwCyjsEQoAsaPAK2TskY50WEdSibaicPGvx7HkJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkk3FvOdnoPpvDd7evOhicJPhnYouIg9iadCraIibDjUKc59iapGlAibZMichA/640?wx_fmt=png&from=appmsg "")  
  
查看EXP参数，了解执行方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJk439ZtDSbibuHBtdDI0XNQDQWBW1KbCLjcYHSEO7bD4lQGjiaX8iawVm0Q/640?wx_fmt=png&from=appmsg "")  
  
执行EXP，**获得root用户权限**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV93bMhAlxELxnzlBg77YxmJkYv58ktv0yWXXAa2ibw10deBKicBT9l6ZnAicibwfx4an0ca3YufxoPXpFw/640?wx_fmt=png&from=appmsg "")  
  
  
