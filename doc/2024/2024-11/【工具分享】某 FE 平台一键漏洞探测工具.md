#  【工具分享】某 FE 平台一键漏洞探测工具   
M0untainShley  篝火信安   2024-11-27 06:35  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb047dymELPiaibHia8lbForEc7YbE60WicsTqgeYicXibCibfZpFd5q8S9ibhunjsWeYhGMPy5DhGsqVTsMxg/640?wx_fmt=png&from=appmsg "")  
  
### 0x00 简介  
  
该程序是某 FE 平台一键漏洞探测工具，目前支持探测的漏洞类型有16个，同时支持单url以及批量探测。  
### 0x01 开发/运行环境  
### 基于 javafx jdk 1.8 进行开发，使用 jdk 1.8 运行。  
  
#### 0x02 支持探测的漏洞类型  
####   
1. uploadAttachmentServlet 任意文件上传漏洞  
  
1. common_sort_tree.jsp 表达式命令执行&任意文件写入漏洞  
  
1. validate.jsp sql 注入漏洞  
  
1. ProxyServletUtil 任意文件读取漏洞  
  
1. downLoadFiles.jsp 任意文件下载漏洞  
  
1. ShowImageServlet 任意文件读取漏洞  
  
1. videotexMonitor.jsp sql 注入漏洞  
  
1. druid 弱口令漏洞  
  
1. downloadfile.jsp 任意文件下载漏洞  
  
1. parseTree.jsp sql 注入漏洞  
  
1. publicData.jsp sql 注入漏洞  
  
1. /feReport/chartList.jsp sql 注入漏洞  
  
1. /sys/treeXml.jsp sql 注入漏洞  
  
1. ln 登陆绕过漏洞  
  
1. loginService.fe 登陆绕过漏洞  
  
1. OfficeServer.jsp 任意文件上传漏洞  
  
**补充说明**  
- validate.jsp sql注入漏洞  
  
该漏洞存在判定条件为响应状态为 200 即页面存在，可能存在误报，建议使用 sqlmap 做二次确认  
  
路径 /mobile/validate.jsp;?json={"type":"0","relId":"*"}  
  
sqlmap 命令为：python sqlmap.py -u URL --random-agent --level 5 --risk 3 --dbms mssql --tamper=space2comment  
  
- chartList.jsp sql注入漏洞  
  
同上，使用sqlmap对/feReport/chartList.js%70?delId=1&reportId=* 进行检测  
  
  
  
**0x03 运行**  
  
****  
1、输入URL，选择漏洞进行检测，同时支持导入文件批量检测。  
  
注意：只允许上传txt文本文件，请将要检测的url按照 https://www,example.com 格式放置在文本文件中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb047dymELPiaibHia8lbForEc7m0UcbTibtDWMKVvkamXt5pibVWFPrgPJSDLOXItnNiaCX3NxR1Zjz4C0w/640?wx_fmt=png&from=appmsg "")  
  
## 0x04 免责声明  
  
本工具旨在提供安全评估和漏洞扫描等相关服务，但使用本工具时请注意以下事项：  
- 本工具的使用者应对其使用产生的结果和后果负全部责任。本工具仅作为辅助工具提供，不对使用者所进行的操作和决策承担责任。  
  
- 本工具尽力提供准确、及时的信息和评估，但无法保证其完全无误。使用者应自行判断和验证本工具提供的信息，并对使用本工具所产生的结果进行独立评估。  
  
请在使用本工具之前仔细阅读并理解上述免责声明。使用本工具即表示您同意遵守上述条款，并自行承担相应责任。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CQf7uHzmVb3icxXWABkpMvXDJ1aDF6RgkCFLMvzDgLEx7jjY4A1n7yTEc2AZmg5CFFoeHJLb3AiblNHRLVFBqlfw/640?wx_fmt=gif&from=appmsg "")  
```
```  
  
  
