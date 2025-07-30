#  跨平台漏洞扫描器 -- EZ（V1.9.2）   
m-sec-org  网络安全者   2025-01-29 16:10  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
EZ是一款集信息收集、端口扫描、服务暴破、URL爬虫、指纹识别、被动扫描为一体的跨平台漏洞扫描器，渗透测试中，可辅助发现常见的SQL注入、XSS、XXE、SSRF之类的漏洞，通过内置的POC辅助发现Apache Shiro、RabbitMQ、Struts2之类的通用组件漏洞，以及某服VPN、通达OA以及泛微OA之类的被曝出已知漏洞的系统，可谓是外围打点，破局进内网，全面发现漏洞的渗透测试必备武器，EZ在手，shell我有。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0JJXjA8siccwxGtXYOcZ5ktUVBibj2vUk7iaBn02hw73k9AUFI3U4F91pXLCbvyshf5AkzJWWgxVr16ib7lkbRXyPA/640?wx_fmt=jpeg&from=appmsg "")  
  
0x02 安装与使用  
webscan 模块  
  
支持通用程序、通用框架的指纹识别。支持常规漏洞和通用漏洞的扫描，内置Headless爬虫。  
```
主动扫描
./ez webscan --pocs sqli -u "http://www.example.com"
被动扫描
./ez webscan
指定poc
./ez webscan --pocs sqli
仅指纹识别
./ez webscan --disable-pocs all -u "http://www.example.com"
忽略指纹识别
./ez webscan -u "http://www.example.com" -nff
```  
  
servicescan 模块  
```
支持端口扫描、服务识别以及漏洞扫描。
./ez servicescan --hosts 192.168.11.111 --ports 445
```  
  
dnsscan 模块  
```
支持 API 形式和枚举形式的子域名信息搜集。
./ez dnsscan -d example.com
```  
  
brute 模块  
```
支持多种协议的爆破。
./ez brute --hosts 192.168.11.111:22:ssh --users root --passwords root
```  
  
reverse 模块  
```
支持单机部署反连平台。
反连平台部署教程可参考：https://docs.ezreal.cool/docs/EZUSE/ez-reverse
```  
  
crawler 模块  
```
支持 headless 形式的爬虫。
不需要登录的场景
./ez crawler -u "http://www.example.com/index.php"
需要登录的场景
./ez crawler -u "http://www.example.com/index.php" --wait-login
```  
  
web 模块  
```
支持 web 界面对 ez 功能进行操作，也可以进行任务一键下发。
./ez web
EZ 从 1.5.0 版本开始使用 ez web 在启动时会默认设置安全路径为随机串，第一次需访问安全路径后才可正常登录，如果不想有安全路径则添加 --no-safe-path 参数，也可以使用 --safe-path 自定义安全路径.
```  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccweJjGmTv36h552BUgMZTgeicjFibbyEiauYNpO0Bts4Waic3DUxt90icPMThSYG7ZCHTRI7SxPAZa4G5Q/640?wx_fmt=png&from=appmsg "")  
  
  
