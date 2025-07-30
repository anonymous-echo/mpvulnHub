#  SecScan强大的端口扫描与漏洞扫描工具——梭哈！！！   
Secu的矛与盾  Secu的矛与盾   2025-01-21 04:50  
  
# 介绍  
# SecScan 是一款集漏洞探测、端口扫描、指纹识别为一体的安全工具，拥有多样化的漏洞检测方法，支持对目标自动化进行 端口扫描->指纹识别->服务口令探测->漏洞探测 流程，旨在帮助用户/红队选手快速发现漏洞风险，提升漏洞管理效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OQYwpDLv2j8I4LyTgVERJlZKWBFoJWrejbALs8cHcRUYM51hNTHticrJIiaT5B6f4xKdpzA2gmVtsNlTKeE03LNg/640?wx_fmt=png&from=appmsg "")  
##   
## 核心亮点  
  
### 一、强大的漏洞检测能力  
  
  
支持自动漏洞检测、批量漏洞检测，多任务并发检测，多样化的漏洞检测方法帮助你快速发现资产的脆弱点，自动生成检测报告，并以 Excel  
 格式记录检测结果，便于后续分析与管理。工具目前支持**四种**  
检测方法：  
- **自动检测**  
：指定一个url或包含url的文件，识别CMS并自动调用poc进行漏洞检测。  
  
- **全部检测**  
：不识别CMS，调用poc进行全量漏洞检测。  
  
- **选择式检测**  
：按照程序选择方法选择单个或全部漏洞对单个或多个资产进行检测。  
  
- **指定poc文件**  
：对单个或多个资产进行检测。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OQYwpDLv2j8I4LyTgVERJlZKWBFoJWreyxHdQ9ChJpnRbY2KVibIlrbU1ePeEeia6uXwMmTdgKlNuDT6kHnEswmQ/640?wx_fmt=png&from=appmsg "")  
###   
### 二、综合端口扫描  
  
  
综合网络扫描模块，方便一键自动化、全方位安全检测，支持端口扫描、常见服务的爆破、web指纹识别、web漏洞扫描。  
1. **信息收集**  
  
1. 开放端口扫描  
  
1. 端口服务探测  
  
1. **口令爆破**  
  
1. 服务口令爆破：ssh、smb  
  
1. 数据库爆破：mysql、mssql、redis、oracle、...  
  
1. **web扫描**  
  
1. web信息扫描  
  
1. 指纹识别 (12000+ cms、OA、框架)  
  
1. web漏洞扫描 （根据指纹信息精准扫描漏洞，现有poc 550+）  
  
###   
### 三、丰富的内置功能与接口  
  
- **ICP 查询**  
：快速获取目标站点的备案信息。  
  
- **IP 属地查询**  
：定位目标 IP 的地理归属。  
  
- **站点分析**  
：多维度解析目标网站的关键属性，提取一些泄露的敏感信息。  
  
- **CMS 识别**  
：精准识别网站所使用到的技术和框架。  
  
- **DNS 解析**  
：轻松掌握域名解析情况。  
  
###   
### 四、高性能主程序  
  
  
主程序基于 Golang 开发，具备卓越的性能与稳定性，可通过 JSON 格式返回检测结果，便于多种场景下的集成与调用。  
###   
### 五、灵活的开发扩展  
  
  
支持 Python + Golang 联合驱动，提供更大的开发自由度和自定义空间，满足不同用户的个性化需求。  
## 适用场景  
  
  
SecScan  
 为网络安全从业者提供了一站式的检测与分析解决方案，广泛应用于漏洞排查、安全评估、信息资产分析等工作中，为提升网络安全工作效率和准确性提供有力支持。  
  
  
最主要呢，就是作者会不定期更新维护，可以共同维护各种漏洞POC，另外作者的协作平台还有更多实用方便的功能，据说作者正在针对工具进行GUI版本的升级，敬请期待。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OQYwpDLv2j8I4LyTgVERJlZKWBFoJWreusOhkFpibJqicDo8mrPc7UFDNvfrqdtLRsuqia3cjvuPXgZHOibWyMvRug/640?wx_fmt=png&from=appmsg "")  
  
  
项目地址：https://github.com/birdy02-com/SecScan  
  
项目文档：https://www.birdy02.com/docs/secscan  
  
