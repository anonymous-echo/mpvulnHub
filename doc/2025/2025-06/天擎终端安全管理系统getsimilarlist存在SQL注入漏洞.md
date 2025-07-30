#  天擎终端安全管理系统getsimilarlist存在SQL注入漏洞   
原创 Enginge  Enginge   2025-06-03 13:55  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/SEdvtYR5JaYI00RAa1ZTy35yKKkZEN7ElLsNgz8ts6yTA4cMcHfnGFJotpTGKt04nQBy5H1nAkTOUzZ0AqpdKg/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7QRTvkK2qC7JrnsdoLClToqibt8hpbOMria1A1ulmEwmia8svO8Ck3XazRt4c0UCwBicDxLDib8NccJYKIUMA8bf7UQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
人皆知有用之用，而莫知无用之用也。——《庄子》  
  
  
![图片](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_71@2x.png?tp=webp&wxfrom=5&wx_lazy=1 "")  
漏洞详情：  
  
天擎终端安全管理系统getsimilarlist存在SQL注入漏洞，攻击者可通过此漏洞获取敏感信息。会导致数据库敏感信息泄露和重要数据被篡改等情况。  
  
![图片](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_71@2x.png?tp=webp&wxfrom=5&wx_lazy=1 "")  
  
Query：  
```
banner="QiAnXin web server" || banner="360 web server" || body="appid\":\"skylar6" || body="/task/index/detail?id={item.id}"
app.name=="天擎终端安全管理系统"
```  
  
![图片](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_71@2x.png?tp=webp&wxfrom=5&wx_lazy=1 "")  
  
修复方案：  
```
升级至最新版本，官网地址：https://www.qianxin.com/
```  
  
  
回复："250603"可获取POC  
  
