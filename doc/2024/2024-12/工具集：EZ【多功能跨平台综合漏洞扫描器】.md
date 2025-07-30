#  工具集：EZ【多功能跨平台综合漏洞扫描器】   
 风铃Sec   2024-12-26 04:28  
  
### 工具介绍  
  
EZ是一款集信息收集、端口扫描、服务暴破、URL爬虫、指纹识别、被动扫描为一体的跨平台漏洞扫描器，渗透测试中，可辅助发现常见的SQL注入、XSS、XXE、SSRF之类的漏洞，通过内置的POC辅助发现Apache Shiro、RabbitMQ、Struts2之类的通用组件漏洞，以及某服VPN、通达OA以及泛微OA之类的被曝出已知漏洞的系统，可谓是外围打点，破局进内网，全面发现漏洞的渗透测试必备武器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnLdGzqejBq5ibs2Vbjh1y2PTrz4ia4GKf8nh8WotDlOBZCXgl82rlCIljdic7XUTLaGXJJoeZfHZ7Qg/640?wx_fmt=png&from=appmsg "")  
> 注意：EZ 仅提供社区版使用，开放但源码不开源，用户可通过 M-SEC 社区官方或 Github 下载构建好的二进制文件使用。  
  
#### 证书获取地址  
```
```  
  
注册账户，进行证书获取：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnLdGzqejBq5ibs2Vbjh1y2PYVictfARoRMIUyM0Qf5FI2rR9yziaybtcIZjHmic8U3lATDIQcUTvyAcA/640?wx_fmt=png&from=appmsg "")  
### 使用  
#### 主动扫描  
  
EZ 的  
web  
模块主要为主动扫描Web模式，使用命令  
ez web  
启动 Web 入口，并可以使用  
--lic  
参数指定证书：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnLdGzqejBq5ibs2Vbjh1y2P25b9L9Y3D1hEN0EWk6LY3lkjdiaowYTmny5pC2Y5N0HISPTz5dSC2PA/640?wx_fmt=png&from=appmsg "")  
  
启动成功后会在命令行进行安全路径提示，默认为本地的  
8888  
端口，通过浏览器访问  
http://127.0.0.1:8888/安全路径  
，默认密码为  
ez  
，首次登录需要用户自行更改密码，修改密码后即可添加漏扫项目。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnLdGzqejBq5ibs2Vbjh1y2PmyjQxvJjxP1WvTtEJzWwUqEXKUT3VWdhxkiaHm1gL5iaefR39w2kXa2g/640?wx_fmt=png&from=appmsg "")  
### 被动扫描  
  
EZ   
webscan  
模块主要为被动扫描模式，也就是需要将流量代理至  
webscan  
才能进行扫描，使用  
ez webscan  
命令启动  
webscan  
扫描，会默认监听本地 127.0.0.1 的 2222 端口，也可使用  
—listen  
参数自定义监听端口，比如  
ez webscan --listen 0.0.0.0:1024  
，即可将本地监听端口从默认的 2222 端口更改至 1024 端口.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnLdGzqejBq5ibs2Vbjh1y2PibHUzO7REP7xicRkbjgeofI0VCHA4YjXlXRX036z4wJ00ftATiaYYg4VQ/640?wx_fmt=png&from=appmsg "")  
##### EZ官方文档：  
```
```  
##### 项目地址：  
```
```  
  
