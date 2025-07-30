#  宏景人力资源管理系统 searchCreatPlanList.do SQL注入漏洞(CNVD-2025-6953)   
云梦DC  云梦安全   2025-04-27 01:10  
  
### 一：产品介绍   
  
宏景人力资源管理系统是一款专业、高效的一体化HR管理平台，涵盖组织架构、招聘管理、员工档案、考勤薪资、绩效培训等核心模块，通过智能化流程与数据分析助力企业实现人力资源数字化转型升级。系统支持云端/本地部署，提供灵活配置与移动端应用，有效提升管理效率、降低人力成本，满足中大型企业复杂管理需求，同时确保数据安全与合规性。  
### 二：漏洞描述   
  
宏景人力资源管理系统（HCM）的 searchCreatPlanList.do 接口存在 SQL注入漏洞，攻击者可利用该漏洞构造恶意请求，向数据库注入非法SQL指令，从而窃取、篡改或删除敏感数据（如员工信息、薪资记录等）。该漏洞可能由于未对用户输入进行严格过滤或参数化查询导致，属于高危安全风险，建议企业及时更新补丁或采取防护措施（如WAF、输入校验等）以避免数据泄露风险。  
### 三：复现环境   
```
```  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpywWFGcowDD0H4TUjnA63KRTB1GlS6bsXv2DcTx9M4EDRdibNkZvF1ibBGNKjbbVtsjicwXRicwNTXJDg/640?wx_fmt=png&from=appmsg "")  
### 四：漏洞复现   
  
POC如下  
  
权限绕过，获取cookie  
```
```  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpywWFGcowDD0H4TUjnA63KRibQjPiaKibd7uyYcia1FYCicvBuWXas23ia7QWCQ3tE9DBrf7E4YYlpqiaUkQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
携带cookie注入  
```
```  
  
  
  
