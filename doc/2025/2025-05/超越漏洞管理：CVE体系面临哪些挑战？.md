#  超越漏洞管理：CVE体系面临哪些挑战？   
 FreeBuf   2025-05-10 10:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![伪造社保报表钓鱼邮件](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3934rLGjsK1zaIhu1xDBQxR5uYicx1n4IA033KY92pTk6ibZfGcaITpA4751FzScTAicO8J9c8FWGUmw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞管理的被动性叠加政策流程的延迟，使安全团队不堪重负。根据我们漏洞运营中心（VOC）的数据分析，在68,500个客户资产中发现了1,337,797个独立安全事件，其中32,585个为不同CVE（通用漏洞披露）编号，10,014个CVSS（通用漏洞评分系统）评分≥8分。外部资产存在11,605个独特CVE，内部资产则高达31,966个。面对如此庞大的漏洞数量，部分漏洞未能及时修补导致系统沦陷已不足为奇。  
  
   
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3934rLGjsK1zaIhu1xDBQxRm6Dd1VBVJ5SqvTXVklr7nj8vFVB4kZllACRo0LNPJ6m4GhcBNgf2EA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
本文将探讨漏洞报告现状、基于威胁和利用可能性的优先级排序方法，分析统计概率并简要讨论风险应对。最后我们将提出降低漏洞影响的解决方案，同时为管理团队提供危机响应的灵活策略。  
  
### Part01  
## CVE体系的局限性  
###   
  
  
西方国家普遍采用由MITRE和NIST（美国国家标准与技术研究院）主导的CVE和CVSS体系。截至2025年4月，运行25年的CVE项目已发布约29万条记录（含"已拒绝"和"延期"条目）。NIST国家漏洞数据库（NVD）依赖CVE编号机构（CNA）进行初始评估，这种机制虽提升效率但也引入偏差。研究者与厂商对漏洞严重性的分歧常导致关键漏洞披露延迟。  
  
  
2024年3月的行政延误造成NVD积压24,000条未处理的CVE记录。2025年4月，美国国土安全部终止与MITRE的合同更引发行业对CVE体系未来的担忧，所幸在业界强烈反响下最终延续了资金支持。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3934rLGjsK1zaIhu1xDBQxRoaic4Kt0794Ntfe4jNLg5ic8nN8ndNpGhGp16zxRwWwqr0wMfXy6MdZA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
中国自2009年运营的CNNVD漏洞库虽具技术价值，但受政治因素影响难以国际合作。值得注意的是，并非所有漏洞都会立即披露（形成盲区），而未被发现的零日漏洞更持续被利用。2023年谷歌威胁分析组（TAG）和Mandiant共发现97个零日漏洞，主要影响移动设备、操作系统和浏览器。相比之下，CVE词典中仅约6%的漏洞曾被利用，2022年研究显示半数企业每月仅修复15.5%或更少的漏洞。  
  
### Part02  
## 威胁情报驱动的决策  
##   
###   
  
  
尽管存在缺陷，CVE系统仍提供有价值的漏洞情报。为应对海量漏洞，需优先处理最可能被利用的威胁。事件响应与安全团队论坛（FIRST）开发的EPSS（漏洞利用预测评分系统）能预测漏洞在野利用概率。安全团队可据此选择广泛修补策略或重点防御关键漏洞，两者各有利弊。  
  
  
为验证覆盖范围与效率的平衡，我们分析某公共部门客户的397个漏洞扫描数据。如图所示，当考虑前264个漏洞时，利用概率的缩放计算已接近100%，而此时最高单个漏洞EPSS评分仍低于11%。这说明在系统规模扩大时，仅依赖EPSS进行优先级排序将面临巨大挑战。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3934rLGjsK1zaIhu1xDBQxRGUoMTQoUnTn1mtxZ0lYuiad8ibUGUicMqD9C58XY7Jeu04lUy3wKQibp5w/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part03  
### 攻击者的成功概率  
  
  
通过概率模型分析可得出三个关键结论：  
  
  
1. 攻击者成功率随目标系统数量呈指数增长：针对100个系统时，中等技能攻击者的成功概率已接近100%  
  
2. 企业内网通常存在数千台设备，单点突破即可横向移动  
  
3. 专业渗透测试人员对互联网目标的平均成功率约为30%  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3934rLGjsK1zaIhu1xDBQxRXLxRwYs0xh79yP7EzgBUGYswiaqsztCYQdxbibSt52QiciauA5CbWY0STA/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part04  
## 重构漏洞管理范式  
###   
  
  
当前以CVE为核心的漏洞管理模式已难以应对挑战，建议转向"威胁缓解"与"风险降低"双轨制：  
  
  
**威胁缓解措施**  
  
1. 重点防护互联网暴露面系统  
  
2. 动态响应流程整合补丁、配置调整、补偿控制等手段  
  
3. 将EPSS作为威胁情报的辅助工具  
  
  
**风险降低策略**  
  
1. 收缩攻击面：清理未管理的互联网暴露资产  
  
2. 限制影响范围：通过网络分段、零信任架构控制横向移动  
  
3. 提升基线安全：系统化减少漏洞数量与严重性，优先投资回报率高的改进  
  
   
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3934rLGjsK1zaIhu1xDBQxRJ8EjzT429Bu2ia7oF7MDqvicnxySr9r8Xq9ichQ3yKL49e3USVlgQow2g/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part05  
## 2030安全战略框架  
##   
###   
  
  
未来安全建设应关注：  
  
1. 源头治理：将安全融入系统设计与供应链管理  
  
2. 威胁建模：通过攻防演练验证防御有效性  
  
3. 架构革新：实施SASE和零信任战略  
  
4. 默认安全：建立强制性的安全基线标准  
  
  
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320090&idx=1&sn=cb1b7e4d9fbfa8c98cf0c378da407981&scene=21#wechat_redirect)  
  
### 电台讨论  
  
[]()  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  
  
