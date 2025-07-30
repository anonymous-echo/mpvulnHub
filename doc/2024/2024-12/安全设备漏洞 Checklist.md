#  安全设备漏洞 Checklist   
原创 老鑫安全  老鑫安全   2024-12-13 09:31  
  
弯刀划过红玫瑰，爱我yao家英雄会  
  
2024年最后一个有可能一举翻身的机会  
# 安全设备漏洞 Checklist  
  
##### 【免责声明】本项目所涉及的技术、思路和工具仅供学习，任何人不得将其用于非法用途和盈利，不得将其用于非授权渗透测试，否则后果自行承担，与本项目无关。使用本项目前请先阅读法律法规。  
## 一、身份与访问控制  
### 0x01 堡垒机  
#### 齐智堡垒机  
  
FOFA：  
```
```  
##### 默认口令  
```
```  
##### shterm命令执行 tui.update.php  
```
```  
##### 前台命令执行 cluster_manage.php CNVD-2019-20835  
  
访问以下路径，返回 ok：  
```
```  
  
写入webshell：  
```
```  
```
```  
##### 后台命令执行 data_provider.php CNVD-2019-17294  
```
```  
##### 任意用户登录  
```
```  
#### H3C SecPath  
  
FOFA：  
```
```  
#### Teleport 堡垒机  
  
FOFA：  
```
```  
##### 任意用户登录  
  
返回 code 为 0 说明成功，刷新首页即可进入后台：  
```
```  
##### 后台文件读取  
```
```  
### 0x02 IMC  
#### H3C IMC 智能管理中心  
  
FOFA：  
```
```  
```
```  
```
```  
##### 远程代码执行  
```
```  
## 二、网络检测与响应  
### 0x01 蜜罐  
### 0x02 IDS  
#### 绿盟 UTS 综合威胁探针  
##### 管理员任意登录  
  
输入 admin/任意密码，点击登录。更改响应包，将 {"status":false,...} 中的 false 改为 true，此时，响应包将泄露 admin 用户密码的 md5 值。  
  
利用 md5 值登录页面：  
```
```  
### 0x03 防火墙  
#### 安恒 明御WEB应用防火墙  
  
FOFA：  
```
```  
##### report.php 任意用户登录✅  
  
漏洞指纹：  
```
```  
#### Cisco ASA  
```
```  
##### 拒绝服务/敏感信息获取 CVE-2018-0296  
  
exp：  
- https://github.com/yassineaboukir/CVE-2018-0296  
  
- https://github.com/milo2012/CVE-2018-0296  
  
##### 任意文件删除 CVE-2020-3187  
  
exp：  
- https://packetstormsecurity.com/files/158648/Cisco-Adaptive-Security-Appliance-Software-9.7-Arbitrary-File-Deletion.html  
  
##### 目录穿越/任意文件读取 CVE-2020-3452  
  
漏洞影响  
```
```  
```
```  
#### H3C SecPath下一代防火墙  
  
FOFA：  
```
```  
##### 任意文件下载 ✅  
```
```  
```
```  
#### 奇安信 网康下一代防火墙  
  
FOFA：  
```
```  
##### 远程命令执行 ✅  
```
```  
  
访问：  
```
```  
#### 启明星辰 天清汉马USG防火墙  
##### 默认口令  
```
```  
#### 佑友防火墙  
##### 默认口令  
```
```  
##### 后台命令执行  
```
```  
#### ZeroShell  
  
FOFA：  
```
```  
##### ZeroShell 3.9.0 cgi-bin/kerbynet 命令执行  
  
exp：  
- https://www.exploit-db.com/exploits/49096  
  
### 0x04 网关  
#### 奇安信 网康 NS-ASG 安全网关  
  
FOFA：  
```
```  
##### 任意文件读取 ✅  
```
```  
#### 安恒 明御安全网关  
##### 命令执行/任意文件读取✅  
  
漏洞指纹：  
```
```  
#### 锐捷 EG 易网关  
##### 管理员账号密码泄露 ✅  
  
获取账号密码：  
```
```  
##### branch_passw.php 远程命令执行 ✅  
  
发送请求包：  
```
```  
  
再访问：  
```
```  
##### cli.php 远程命令执行 ✅  
  
发送请求包：  
```
```  
##### download.php 任意文件读取 ✅  
  
poc：  
```
```  
#### 锐捷 ISG 视频接入安全网关  
##### 账号密码泄露漏洞 ✅  
  
FOFA：  
```
```  
  
F12 查看到账号密码，解密md5 后登陆系统。  
### 0x05 路由器  
#### D-Link DAP-2020  
  
FOFA：  
```
```  
##### webproc 任意文件读取 CVE-2021-27250 ✅  
  
poc：  
```
```  
#### H3C 企业路由器（ER、ERG2、GR系列）  
##### 任意用户登录漏洞 ✅  
  
攻击者可通过访问 /userLogin.asp/../actionpolicy_status/../xxxx.cfg 接口，xxxx 为设备型号（比如设备型号为 ER5200G2，即访问 /userLogin.asp/../actionpolicy_status/../ER5200G2.cfg），绕过 COOKIE 验证，进行目录穿越，获取设备的明文配置文件。  
  
配置中有明文的 Web 管理员账号 admin 密码，登录后台可通过开启 telnet 获取命令执行权限。  
#### iKuai 路由器  
  
FOFA：  
```
```  
##### 后台任意文件读取✅  
  
默认密码：admin/admin  
  
poc：  
```
```  
##### 流控路由 SQL注入漏洞✅  
  
万能密码登录：  
```
```  
#### 锐捷 NBR路由器  
##### 远程命令执行漏洞 CNVD-2021-09650 ✅  
  
FOFA：  
```
```  
  
构造命令执行：  
```
```  
  
再访问：  
```
```  
### 0x06 负载均衡  
#### Citrix ADC  
##### 默认口令  
```
```  
##### 远程代码执行 CVE-2019-19781  
  
访问以下链接，返回403则表示不存在漏洞，返回smb.conf则证明漏洞存在。  
```
```  
  
exp：  
- https://github.com/trustedsec/cve-2019-19781  
  
- https://github.com/jas502n/CVE-2019-19781  
  
#### F5 BIG-IP  
##### 远程代码执行 CVE-2020-5902  
  
exp：  
- https://github.com/jas502n/CVE-2020-5902  
  
- https://github.com/theLSA/f5-bigip-rce-cve-2020-5902  
  
##### 远程代码执行 CVE-2021-22986  
```
```  
  
exp：  
- https://github.com/h4x0r-dz/RCE-Exploit-in-BIG-IP  
  
- https://github.com/Al1ex/CVE-2021-22986  
  
#### 天融信 Top-app LB  
##### SQL注入  
```
```  
#### 无密码登录  
```
```  
### 0x07 VPN  
#### Fortigate SSL VPN  
  
FOFA：  
```
```  
##### 密码读取 CVE-2018-13379  
  
exp：  
https://github.com/milo2012/CVE-2018-13379  
##### 任意密码重置 CVE-2018-13382  
  
exp：  
https://github.com/milo2012/CVE-2018-13382  
##### 认证绕过 CVE-2022-40684  
  
exp：  
https://github.com/horizon3ai/CVE-2022-40684  
```
```  
#### Palo Alto SSL VPN  
##### GlobalProtect 远程代码执行 CVE-2019-1579  
  
exp：  
https://github.com/securifera/CVE-2019-1579  
#### Pulse Secure SSL VPN  
##### 任意文件读取 CVE-2019-11510  
  
exp：  
https://github.com/projectzeroindia/CVE-2019-11510  
##### 远程代码执行 CVE-2019-11539  
  
exp：  
https://github.com/0xDezzy/CVE-2019-11539  
#### 深信服 VPN  
##### 常见密码  
```
```  
##### 口令爆破  
  
用户登录，若多次尝试登录失败会要求输入验证码，若输入错误的验证码，会提示“校验码错误或校验码已过期”；修改登录请求的数据包，清空cookie和验证码字段的值即可绕过验证码，此时提示“用户名或密码错误”。  
```
```  
##### 短信绕过  
```
```  
##### 任意密码重置  
  
加密算法使用了默认的key，攻击者构利用key构造重置密码数据包从而修改任意用户的密码。利用需要登陆账号。  
- M7.6.6R1版本key为20181118  
  
- M7.6.1key为20100720  
  
```
```  
```
```  
#### 锐捷 SSL VPN  
  
FOFA：  
```
```  
##### 越权访问  
- UserName 参数为已知用户名  
  
```
```  
#### Juniper SSL VPN  
- Juniper SSLVPN / JunOS RCE and Multiple Vulnerabilities  
  
## 三、终端响应与检测  
### 0x01 EDR/杀软  
#### 深信服 EDR  
##### 命令执行1  
  
exp：  
https://github.com/BH2UOL/sangfor-edr-exploit  
##### 命令执行2  
```
```  
##### 后台任意用户登录  
```
```  
#### 360天擎  
  
FOFA：  
```
```  
##### 前台SQL注入  
```
```  
##### 数据库信息泄露  
```
```  
#### 金山 V8 终端安全系统  
  
FOFA：  
```
```  
##### 任意文件读取  
```
```  
##### pdf_maker.php 命令执行  
```
```  
#### 金山 VGM防毒墙  
  
FOFA：  
```
```  
##### downFile.php 任意文件读取  
  
poc：  
```
```  
### 0x02 数据防泄漏系统  
#### 天融信数据防泄漏系统  
##### 越权修改管理员密码  
  
无需登录权限,由于修改密码处未校验原密码,且 /?module=auth_user&action=mod_edit_pwd 接口未授权访问,造成直接修改任意用户密码。 默认 superman 账户 uid 为 1。  
```
```  
## 四、其他  
### 0x01 网络摄像机  
#### Hikvision DS/IDS/IPC 等设备  
  
FOFA：  
```
```  
##### 远程命令执行 CVE-2021-36260 ✅  
```
```  
### 0x02 综合管理平台  
#### 大华 智慧园区综合管理平台  
  
FOFA：  
```
```  
##### user_save.action 任意文件上传 ✅  
  
漏洞指纹：  
```
```  
```
```  
#### 大华 城市安防监控系统平台管理  
  
FOFA：  
```
```  
##### attachment_downloadByUrlAtt.action 任意文件下载 ✅  
  
poc：  
```
```  
#### Hikvision iVMS-8700综合安防管理平台  
  
FOFA：  
```
```  
##### 任意文件下载 ✅  
  
验证POC，token 为 URL md5：  
```
```  
##### 任意文件上传 ✅  
  
发送请求包上传文件：  
```
```  
  
访问webshell：  
```
```  
  
大家伙，如果想学习更多的芝士，可以看我们的论坛：  
  
https://www.laoxinsec.com/  
  
哔哩哔哩有免费课程，搜索账号：老鑫安全培训，老鑫安全二进制  
  
进群二维码：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2dWjM9j3fnC7gHm9zob1kxAIk13LbWcsIsyOpys3To4ysErIzDudGaLpUtG6Y6CKY2h8X3dv5icvog/640?wx_fmt=jpeg&from=appmsg "")  
  
老鑫：  
前Wooyun核心白帽子，痴迷底层技术，在二进制方向有一定技术积累，后从事网安培训多年，截止目前已培训350+学员，培训学员遍布各大安全企业及机关单位。除二进制，web安全、安全开发、逆向等安全技术均有涉及。公众号：studentSec    
  
濠哥：奇安信粤东安全运营中心技术专家（牛逼的老师不需要简介）  
  
下面是关于我们的培训课程，如有需求，可以加入我们的微信群联系  
群主：  
  
**课程结构**  
  
  
基础课程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2cyAvDe8pWIE34YezWecWVXaL3rpXoAMdkge6VI5qLzncznlXyQiaHP84MGpp1fRjS7pIOZicpFjpibA/640?wx_fmt=png&from=appmsg "")  
  
进阶课程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2cyAvDe8pWIE34YezWecWVXITlG9pSwazPzGp1jwU7UF3mg3h5CFkBpTfxtiawF0h3sHcJMUTDoJ7w/640?wx_fmt=png&from=appmsg "")  
  
  
  
