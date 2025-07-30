#  【漏洞情报】九思协同办公系统存在SQL注入漏洞   
cexlife  飓风网络安全   2024-12-02 14:37  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01XJibsmJicSqrqKF7PSx0vcxJTYtY72PsTVM9nMKrHaCos0fkSNTLkMRs8qIruJrm6FBlxicNg3mcvA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**九思协同办公系统/jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr存在SQL注入漏洞,可利用该漏洞获取数据库中的敏感信息等,未经授权的攻击者可以通过该漏洞获取数据库敏感信息。**临时修复建议:**1、加强系统和网络的访问控制，修改防火墙策略，不将非必要服务暴露于公网;2、如果目前无法升级，若业务环境允许，使用白名单限制应用服务端口的访问来降低风险;3、定期对服务器上的网站后门文件进行及时查杀。**通用修复建议:**联系厂商,更新应用至安全版本。  
  
