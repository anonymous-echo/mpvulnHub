#  Bazaar v1.4.3 任意文件读取漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-06 23:59  
  
## 1. 漏洞描述  
  
    Bazarr存在任意文件读取漏洞，该漏洞是由于Bazaar v1.4.3的组件/api/swaggerui/static中存在一个问题，允许未经身份验证的攻击者可利用该漏洞执行目录遍历。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKGS0Z00JkDuBdiciawKX3picRASiaToHbIq8rGcun6xE4Rzl6icXVj6S4n4w/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKF2EscK5aRt7Ng98tkbOvGdJiaNByIHQ24InAvzDUluRItDwKkEJP6og/640?wx_fmt=png&from=appmsg "")  
  
  
