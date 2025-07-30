#  渗透测试新利器！EZ漏洞扫描器全面解析   
原创 SecCeo  泷羽Sec-Ceo   2025-02-28 11:06  
  
#  EZ   
## 工具介绍  
  
EZ是一款集信息收集、端口扫描、服务暴破、URL爬虫、指纹识别、被动扫描为一体的跨平台漏洞扫描器，渗透测试中，可辅助发现常见的SQL注入、XSS、XXE、SSRF之类的漏洞，通过内置的POC辅助发现Apache Shiro、RabbitMQ、Struts2之类的通用组件漏洞，以及某服VPN、通达OA以及泛微OA之类的被曝出已知漏洞的系统，可谓是外围打点，破局进内网，全面发现漏洞的渗透测试必备武器，EZ在手，shell我有。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/zzUI49wvajDFPW169iamomepxpYCDLFYTicwE854AB2jcZzvbRBxhJSDlK6kJLFtBCSsRfoCicCQ2iady8SMaGmHjQ/640?wx_fmt=jpeg&from=appmsg "")  
### 项目地址：  
```
https://github.com/m-sec-org/EZ.git
```  
## 一、EZ核心功能速览  
### 多维度资产探测  
- **子域名搜集**  
（dnsscan模块）：通过API或枚举快速发现目标域名下的子站点。  
  
- **端口扫描与服务识别**  
（servicescan模块）：精准识别开放端口及服务类型，支持漏洞扫描。  
  
- **URL爬虫（crawler模块）**  
：Headless爬虫自动抓取目标站点链接，支持登录场景。  
  
### 漏洞检测全覆盖  
- **主动扫描**  
：内置POC库，支持Apache Shiro、Struts2等组件漏洞检测。  
  
- **被动扫描**  
：结合浏览器插件**EzHelper**  
，无需安装SSL证书即可实时捕获流量并分析漏洞。  
  
- **协议爆破**  
（brute模块）：支持SSH、RDP等协议爆破，快速突破入口。  
  
### 指纹识别黑科技  
- 基于HTTP畸形报文响应技术，精准识别组件核心功能点。  
  
- 可禁用指纹识别（-nff参数）或仅执行指纹探测（--disable-pocs all）。  
  
## 二、简单使用  
- **快速检测SQL注入漏洞**  
  
```
./ez webscan --pocs sqli -u "http://www.example.com"
```  
- **子域名搜集**  
  
```
./ez dnsscan -d example.com
```  
- **端口扫描与漏洞检测**  
  
```
./ez servicescan --hosts 192.168.11.111 --ports 445
```  
- **爆破SSH服务**  
  
```
./ez brute --hosts 192.168.11.111:22:ssh --users root --passwords root
```  
## 三、EZ的六大技术亮点  
1. **精准低干扰**  
  
采用**HTTP Request Reduce技术**  
，最小化漏洞扫描时的请求数量，降低对业务的影响。  
  
1. **POC高度自定义**  
  
支持YAML和Go编写自定义漏洞检测脚本，灵活适配实战需求。  
  
1. **原生协议识别**  
  
通过底层协议交互精准获取服务信息，识别率远超传统工具。  
  
1. **反连平台集成**  
  
一键部署反连服务器（reverse模块），轻松捕获盲注类漏洞。  
  
1. **Web界面管理**  
  
通过./ez web启动可视化界面，任务下发、结果查看更直观。  
  
1. **社区生态支持**  
  
依托**M-SEC社区**  
，每日更新漏洞情报与POC插件，实战能力持续进化。  
  
#  红队全栈教学   
  
可在公众号回复“**红队**  
”获取群链接  
#  OSCP+   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zzUI49wvajCD0dwfS6EkZHkUkyaAD1iaWibkN1xNlIn1nDoDgyVC1wSSkzUCncFtAxaJKb6lA9kOn9x1icNz1Fk0A/640?wx_fmt=png&from=appmsg "")  
  
  
  
