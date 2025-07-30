#  全球各地的工业PLC受到CODESYS V3 RCE漏洞的影响   
布加迪  嘶吼专业版   2023-08-18 14:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29dova2gibQXa5xnNOJlUhUt6AFvntPWcqTrsKJFBhQ9dtCHywJ71T2mbUSICVdUH0TdPibYdfGccAA/640?wx_fmt=png "")  
  
全球工业环境中使用的数百万PLC（可编程逻辑控制器）面临CODESYS V3软件开发工具包（SDK）中15个漏洞的风险，这些漏洞为远程代码执行（RCE）和拒绝服务（DoS）攻击提供了可趁之机。  
  
如今全球500余家设备制造商使用CODESYS V3 SDK，根据IEC 61131-3标准对1000多个PLC型号进行编程，以便用户开发定制的自动化序列。  
  
该SDK被广泛使用，为工程师配置和测试用于工业系统的PLC提供了一种开发环境。大量PLC中的固件含有CODESYS提供的库程序以运行工程师们编写的程序，而可以被利用的正是这嵌入的代码，导致设备容易受到攻击。  
  
该SDK还提供了一个Windows管理界面和一个模拟器，允许用户在部署到生产环境之前先测试其PLC配置和所编的程序。  
  
CODESYS V3 SDK中的15个漏洞是由微软研究人员发现的，他们于2022年9月向总部位于德国的CODESYS报告了这些漏洞。这家厂商于2023年4月发布了安全更新以解决已发现的问题。  
  
由于这些设备具有的性质，它们不常更新以修复安全问题，因此微软的安全团队昨天发布了一篇详细的文章，以提高人们对这一风险的认识，并帮助加快修补。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29dova2gibQXa5xnNOJlUhUtibNKJtxdhrxpx9YIcibMO8JMncNOLHr999pnjcFMvvgHf5thAPYOiayMA/640?wx_fmt=png "")  
  
图1.在互联网上曝光的CODESYS设备（图片来源：微软）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29dova2gibQXa5xnNOJlUhUtEC3aXMohAgDP7ef15pmIqNwOI0KXAHqZTibVCtLq1iaoBicm66XycDU6w/640?wx_fmt=png "")  
   
CODESYS漏洞  
  
微软仔细检查了施耐德电气和WAGO这两家厂商使用CODESYS V3的的两款PLC，结果发现了15个高危漏洞（CVSS V3：7.5 - 8.8），其中12个漏洞是缓冲区溢出漏洞。  
  
这些漏洞分别是：CVE-2022-47378、CVE-2022-47379、CVE-2022-47380、CVE-2022-47381、CVE-2022-47382、CVE-2022-47383、CVE-2022-47384、CVE-2022-47385、CVE-2022-47386、CVE-2022-47387、CVE- 2022-47388、CVE-2022-47389、CVE-2022-47390、CVE-2022-47392和CVE-2022-47393。  
  
主要问题出在SDK的标记解码机制上，具体来说是指标记在没有验证大小的情况下被复制到设备缓冲区中，这给攻击者提供了缓冲区溢出的机会。这些标记是数据或数据结构的载体，为PLC的正常运行提供了关键指令。  
  
缓冲区溢出问题并不是孤立的，微软还在CODESYS V3 SDK的15个组件中发现了这个问题，包括CMPTraceMgr、CMPapp、CMPDevice、CMPapp、CMPAppBP、CMPAppForce和CMPFileTransfer。  
  
虽然这些漏洞需要身份验证才能被利用，但微软表示，可以通过使用CVE-2019-9013来规避这个要求，而CVE-2019-9013是另一个影响CODESYS V3的漏洞，在传输过程中以明文形式暴露用户凭据，如下所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29dova2gibQXa5xnNOJlUhUtQNTXF5IjsP783qCftdxuQyAHu8jjs7o8a6vBsDfkNE0JKznuqMpF9Q/640?wx_fmt=png "")  
  
微软的分析师试了15次，结果发现有12次能够利用该漏洞在PLC上远程执行代码。  
  
如果产品运行的是3.5.19.0之前的版本，无论硬件和操作系统配置如何，都会受到影响，**CODESYS的安全公告列出了以下受影响的产品：**  
  
CODESYS Control RTE（SL）  
  
CODESYS Control RTE（for Beckhoff CX）SL  
  
CODESYS Control Win（SL）  
  
CODESYS Control Runtime System Toolkit  
  
CODESYS Safety SIL2 Runtime Toolkit  
  
CODESYS Safety SIL2 PSP  
  
CODESYS HMI（SL）  
  
CODESYS Development System V3  
  
CODESYS Development System V3 simulation runtime  
  
**除上述产品外，如果运行4.8.0.0之前的版本，以下产品也会受到影响：**  
  
CODESYS Control for BeagleBone SL  
  
CODESYS Control for emPC-A/iMX6 SL  
  
CODESYS Control for IOT2000 SL  
  
CODESYS Control for Linux SL  
  
CODESYS Control for PFC100 SL  
  
CODESYS Control for PFC200 SL  
  
CODESYS Control for PLCnext SL  
  
CODESYS Control for Raspberry Pi SL  
  
CODESYS Control for WAGO Touch Panels 600 SL  
  
建议管理员尽快升级到CODESYS V3 v3.5.19.0，同时微软还建议断开PLC及其他关键工业设备与互联网的连接。  
  
正如微软警告的那样：“如果威胁分子针对使用CODESYS高危版本的设备发动DoS攻击，就可以关闭发电厂，而远程代码执行可以在设备中植入后门，让攻击者得以篡改设备操作，导致PLC运行异常，或者窃取关键信息。”  
  
参考及来源：https://www.bleepingcomputer.com/news/security/industrial-plcs-worldwide-impacted-by-codesys-v3-rce-flaws/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29dova2gibQXa5xnNOJlUhUtzxTAnGES4OReTuTG32kWmYIl3H8eMZeaj8AsbcrkeQKJl2EvXWkT2Q/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
