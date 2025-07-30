#  重点系统指纹漏洞验证工具 -- Catcher   
wudijun  Web安全工具库   2025-02-11 16:01  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
Catcher(捕手) 重点系统指纹漏洞验证工具，适用于外网打点，资产梳理漏洞检查。在面对大量的子域名时，Catcher可将其进行指纹识别，将已经识别成功的指纹进行对应的漏洞验证，并对域名进行cdn判断，将未使用cdn域名进行端口扫描  
  
![1](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziaWBysUKz6TBwPoQrLRsfLNZxWLpVD0HQBKI5xsnuTSbtWD8cv2bxSpw/640?wx_fmt=png&from=appmsg "")  
  
0x02 安装与使用  
1.Catcher首先会对域名通过finger.json文件进行指纹识别  
  
![3](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziaAwFAVFTq9HWj2j5NIolckkjPezBIuFDJTnRs9raxuFFQLg91eLg4UA/640?wx_fmt=png&from=appmsg "")  
  
2.识别成功后会进入poc文件下去找具体对应的poc进行测试  
  
比如识别到的指纹为Atlassian Confluence，那么就会进入到 poc文件下的Atlassian Confluence文件下，去运行该文件中所有的poc文件  
  
![4](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziaLX8sXLOBzfTu6IzXGhVWkC866CahOViajm6rUdhaRhOvBHoYmJiaiclMQ/640?wx_fmt=png&from=appmsg "")  
  
Catcher中内置了许多用于漏洞验证的poc  
  
![5](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziakYfRSJMbRVD5PvTGHTibhO6SEO7xtBCPVGJz2mjE2TPSLibQ1JChyylw/640?wx_fmt=png&from=appmsg "")  
  
![6](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziaezH6vtv2gUicFd5iaYibbJEy1TS1uHsGPDzZz3M1XLudOyGWZmVESBPUQ/640?wx_fmt=png&from=appmsg "")  
  
后续会继续更新指纹以及poc  
  
3.进行完漏洞测试后会将所有域名进行cdn判断（不可能做到绝对准确）  
  
4.判断完cdn后会去获取域名对应的ip，并进行端口扫描  
  
5.运行结束后会将结果保存到results文件下  
  
![7](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1zia0vvq8X3pWhS9d536b935Eeff2vboicu3nURcXnFP2TUdn7LLhGzBB6w/640?wx_fmt=png&from=appmsg "")  
  
该文件下有7个文件  
  
Cdn.txt: 使用了cdn的域名  
  
NoCdn.txt: 没有使用cdn的域名  
  
ErrorCdn.txt: 未判断出是否使用cdn的域名  
  
Finger.json: 指纹识别到的域名  
  
NoFinger.json: 未指纹识别到的域名  
  
PocResults.txt: 漏洞测试的结果  
  
Ports.txt: 端口扫描结果  
  
在查看结果时推荐使用sublime等编译器打开查看，文本文档直接打开不太友好  
  
![8](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziaXIg89ZPl5d0haMZjniaRy1WAeZvE5ib6xVZmOmDaHdpia025tiad4GuJlg/640?wx_fmt=png&from=appmsg "")  
  
除了对多个域名进行指纹识别漏洞验证  
  
因为domain.txt中也可写入ip端口的形式，并且Catcher中有很多poc。  
  
对多个资产、单个资产进行批量的泛微OA、用友OA等漏洞验证也是不错的选择  
  
![10](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziajyPG8G60GxV4QqVL5mAzn3NIbOeBRNavNZjfiaNZ0PfItGTqtyib3OKQ/640?wx_fmt=png&from=appmsg "")  
  
![9](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibsmicc3Got9A8uaDgOyRN1ziauOO0PIIQib8feFViaic6S9ooKiaPwcT0vwX2vLjYricd5LWfwqFRbaAicO6w/640?wx_fmt=png&from=appmsg "")  
  
  
  
**·****今 日 推 荐**  
**·**  
  
> 《Linux系统管理与网络管理（第3版）》共26章，分为3篇。第1篇“基础知识”，涵盖的内容有Linux系统简介、Linux系统安装、图形桌面系统管理、命令行界面等；第2篇“系统管理”，涵盖的内容有Linux系统启动过程、用户和用户组管理、磁盘分区管理、文件系统管理、软件包管理、进程管理、网络管理、系统监控、Shell编程、Linux系统安全等；第3篇“网络服务管理”，涵盖的内容有Web服务器配置和管理、动态Web服务器配置和管理、DNS服务器配置和管理、邮件服务器配置和管理、DHCP服务器配置和管理、代理服务器配置和管理、NFS服务器配置和管理、Samba服务器配置和管理、NAT服务器配置和管理、MySQL数据库服务器配置和管理、Webmin服务器配置和管理、Oracle服务器配置和管理等。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibuHIuM9siaqBNNnw4HqkS4uc6mkiaDwRXDtb3oVsVYRUpsUFmZYlbvl43EjE0dAqIXrhicicbjMe1OpKQ/640?wx_fmt=png "")  
  
  
