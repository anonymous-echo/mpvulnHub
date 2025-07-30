#  Atlassian Confluence Data Center及Confluence Server远程代码执行漏洞安全风险通告   
原创 QAX CERT  奇安信 CERT   2023-12-06 17:15  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="color: #ffffff;font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="89"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;caret-color: red;letter-spacing: 0px;">Atlassian Confluence Data Center 及 Confluence Server 远程代码执行漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="89"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-46430、CVE-2023-22522</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="89"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="167"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-12-06</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="192"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="109"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">十万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="89"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="letter-spacing:0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="192"><p style="line-height: 1em;"><strong><span style="font-size: 13px;letter-spacing: 0px;">CVSS 3.1分数</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="109"><p style="line-height: 1em;"><span style="color: #ff0000;font-size: 13px;letter-spacing: 0px;"><strong>9.0</strong></span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="89"><p style="line-height:1em;"><span style="font-size:13px;"><strong>威胁类型</strong></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="167"><p style="line-height:1em;"><span style="font-size:13px;">代码执行</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="192"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="109"><p style="line-height:1em;"><span style="color: rgb(255, 169, 0);"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;color: #ff0000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="color: rgb(255, 169, 0);max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">中</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="89"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="192"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="109"><p style="line-height: 1em;"><span style="color: #000000;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="89"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="192"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="109"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">允许经过身份验证的攻击者（包括具有匿名访问权限的攻击者）在受影响的实例上实现远程代码执行。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Atlassian Confluence Data Center是面向大型企业和组织的高可用性、可扩展性和高性能版本，Atlassian Confluence Server是适用于中小型企业和组织的自托管版本。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到**Atlassian Confluence Data Center 及 Confluence Server远程代码执行漏洞(CVE-2023-22522)**  
，该漏洞是由模板注入引起的，经过身份验证的攻击者（包括具有匿名访问权限的攻击者）可以将不安全的用户输入注入 Confluence 页面，最终成功利用此漏洞的攻击者可在受影响的实例上实现远程代码执行。  
  
  
**鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Confluence Data Center and Server 4.x.x  
  
Confluence Data Center and Server 5.x.x  
  
Confluence Data Center and Server 6.x.x  
  
Confluence Data Center and Server 7.x.x  
  
Confluence Data Center and Server 8.0.x  
  
Confluence Data Center and Server 8.1.x  
  
Confluence Data Center and Server 8.2.x  
  
Confluence Data Center and Server 8.3.x  
  
8.4.0 <= Confluence Data Center and Server <= 8.4.4  
  
8.5.0 <= Confluence Data Center and Server <= 8.5.3  
  
8.6.0 <= Confluence Data Center <= 8.6.1  
  
  
**>**  
**>**  
**>**  
**>**  
  
**不受影响版本**  
  
Atlassian Cloud站点  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**受影响资产情况**  
  
奇安信鹰图资产测绘平台数据显示，Atlassian Confluence Data Center及Confluence Server远程代码执行漏洞(CVE-2023-22522)关联的国内风险资产总数为237796个，关联IP总数为9730个。国内风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49GNMwdfCQZbKicQ3sKFtSe9WorqKPSOTHIrYYicA0xQA7pUj8nzDzE2pln8y0IoIMwtaia93aCfL8CQ/640 "")  
  
  
Atlassian Confluence Data Center及Confluence Server远程代码执行漏洞(CVE-2023-22522)关联的全球风险资产总数为504891个，关联IP总数为52201个。全球风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49GNMwdfCQZbKicQ3sKFtSe9tG8MQMAsGPsvNPibrIxx1NABqB7greribrBAZOKL4Dn8qMoCzibY1DRlg/640 "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已有可更新版本，建议受影响用户升级至：  
  
Confluence Data Center and Server 7.19.17 (LTS)   
  
Confluence Data Center and Server 8.4.5  
  
Confluence Data Center and Server 8.5.4 (LTS)  
  
Confluence Data Center >= 8.6.2   
  
Confluence Data Center >= 8.7.1  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
若暂时无法修复，可采取以下缓解措施：  
  
1、限制应用外网可访问IP；  
  
2、建议备份实例，可参考：https://confluence.atlassian.com/doc/production-backup-strategy-38797389.html  
  
  
  
**05**  
  
**参考资料**  
  
[1]https://confluence.atlassian.com/security/cve-2023-22522-rce-vulnerability-in-confluence-data-center-and-confluence-server-1319570362.html  
  
  
  
**06**  
  
**时间线**  
  
2023年12月6日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**漏洞情报服务**  
  
奇安信ALPHA威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibeoC2F6g0jNoibcwyhKK0FGDVva9QSXmhVXRHY4rKhKrI12UTvAAicLIbmNQDCozek3CajwfQyLvQQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49GNMwdfCQZbKicQ3sKFtSe9fj51Z1es86pCicH4rNAXRxyTziaygFfN6Th0uEnJ3cKaicfvNicyHKzH0Q/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到  
**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
