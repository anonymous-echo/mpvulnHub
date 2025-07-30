#  【漏洞复现】高校人力资源管理服务平台系统ReportServer存在敏感信息泄露漏洞   
原创 清风  白帽攻防   2024-12-27 01:03  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
  
  
高校人力资源管理系统通过在线化管理实现了招聘全流程的高效操作，包括职位发布、简历筛选、面试安排、候选人状态跟踪及录用通知等功能。该系统提高了招聘工作的效率和精准度，简化了传统招聘流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cvR7Tjria3yDVgRZribRTSk4CyqS1T9StS0BWcjs2IvSaARMQCRL95fJNiaCghSGol3Uq9lBF4o7fbg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞描述  
  
高校人力资源管理系统的ReportServer接口存在敏感信息泄露漏洞，攻击者可以利用该漏洞获取账号、密码等敏感数据。  
fofa语法```
body="FM_SYS_ID"||body="product/recruit/website/RecruitIndex.jsp"
```  
漏洞复现```
具体poc详情请在公众号知识星球获取
GET xxx HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=1
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cvR7Tjria3yDVgRZribRTSk4YXKT2CjDrG8RqQicKrOK9DAo7cRxVYU4l93bicJ0hjwp1MMrXn8w6zzg/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cvR7Tjria3yDVgRZribRTSk4GfLiajYdeygck4h3RMGEZFibkZ1NLp867rpzSwCK1IfDX1LqgzkJNV4A/640?wx_fmt=png&from=appmsg "")  
修复建议  
打补丁  
  
