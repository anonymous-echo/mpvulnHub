#  新生代免费漏洞扫描器，NextScan，开盒即用   
 张无瑕思密达   2024-08-29 23:42  
  
![](https://mmbiz.qpic.cn/mmbiz_png/V3VOCXDmjRh6v5V3xqfuI56fKkfZUtJmtKyHS9wlSTicHawy6nH6Xryork0FMYrrdib1xuN8kH5OpK5u4GD6WgNQ/640?wx_fmt=png&from=appmsg "")  
  
近两年，开源或者免费的网络安全项目明显不如以前多了，即使是开放出来的项目，很多也已经完全不更新了，百花齐放的日子似乎已经过去了。  
  
这次介绍一个2023年同城旅行公布的免费版漏洞扫描器。  
  
**飞刃（NextScan），是同城旅行自研一款适合企业需求的漏洞扫描平台，基于go语言编写，采用分布式架构，由Server，Agent，Web三个部分组成。拥有信息采集、漏洞扫描、漏洞管理、POC管理、资产管理等功能，支持主动、被动多种扫描模式，支持多种数据来源，支持扫描Web漏洞、主机类漏洞；同城旅行的愿景是希望打造成一个可以开箱即用的企业级黑盒漏洞扫描平台。**  
  
除了有github地址，还有专门的官网文档。  
  
https://github.com/tongcheng-security-team/NextScan/  
  
https://next-scan.ly.com/  
  
在软件安装部署环节，还有专门的国内下载地址：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/V3VOCXDmjRh6v5V3xqfuI56fKkfZUtJmC9HSh1h8AeddCsrpw40wG5bIFtNDdfTLMibeEmGxfdGta8cv8cusKfA/640?wx_fmt=png&from=appmsg "")  
  
用这个扫描器去扫描SRC的资产效果是比较好的，至少常规的漏洞肯定都可以发现，不过对于有WAF的资产还是可以暂时放弃测试直接web漏扫的部分功能，多考虑一下其中的逻辑漏洞比较划算一点。  
  
这个漏扫项目基本可以作为一家企业的漏扫专门工具，非常通用了。  
  
  
