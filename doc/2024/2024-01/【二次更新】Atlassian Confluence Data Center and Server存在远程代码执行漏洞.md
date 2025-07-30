#  【二次更新】Atlassian Confluence Data Center and Server存在远程代码执行漏洞   
安恒研究院  安恒信息CERT   2024-01-20 12:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXesCfIew4xDgxHPaichzoa958OaWgTglXPf5mic3dq7TZc3np7PMDpLQPa4pL89cQvD6FAZaN71atsbA/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody style="box-sizing:border-box;"><tr style="box-sizing:border-box;"><td colspan="4" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;background-color:#4577da;box-sizing:border-box;" width="100.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;color:#ffffff;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:center;"><strong style="box-sizing:border-box;">漏洞概述</strong></p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="75.0000%"><p>Atlassian Confluence Data Center and Server存在远程代码执行漏洞(CVE-2023-22527)</p></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">严重<br/></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">10.0<br/></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><p>CVE-2023-22527</p></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">未分配<br/></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">未分配<br/></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><p>DM-202301-000034</p></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">已发现<br/></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">未发现<br/></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">未发现</td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%">已复现<br/></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="75.0000%"><p>该漏洞允许未经身份验证的攻击者构造恶意请求，对影响版本实现远程代码执行。</p></td></tr></tbody></table>  
  
安恒研究院卫兵实验室已复现此漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXeuomKxpamAxPR2FPIYNiczyia0nj0I6Tx2yJiabMcDyRGmdXSSy6CIdicaGjJQrdDOQeXiaZ07uTK9YaMw/640?wx_fmt=png&from=appmsg "")  
  
 Atlassian Confluence 远程代码执行漏洞(CVE-2023-22527)复现截图  
  
该产品主要使用客户行业分布广泛，漏洞危害性相对较高，建议客户尽快做好自查及防护。  
  
  
  
**漏洞信息**  
  
  
  
  
  
**漏洞描述**  
  
Atlassian Confluence 是一款专为团队  
合作设计的内容协作软件。它使团队能够共同创建、分享和协作编辑文档，从而有效地管理项目知识和信息。Confluence 还集成了多种宏和插件，如日程表、任务列表和Jira集成。  
  
**应急响应等级：**  
1级  
  
**漏洞类型：**  
远程代码执行  
  
  
**影响范围**  
  
影响版本：  
  
8.0.x  
  
8.1.x  
  
8.2.x  
  
8.3.x  
  
8.4.x  
  
8.5.0-8.5.3  
  
安全版本：  
  
Confluence Data Center and Server >= 8.5.4 (LTS)  
  
Confluence Data Center >= 8.6.0 (Data Center Only)  
  
Confluence Data Center >= 8.7.1 (Data Center Only)  
  
  
**CVSS向量**  
  
访问途径（AV）：网络  
  
攻击复杂度（AC）：低  
  
所需权限（PR）：无需任何权限  
  
用户交互（UI）：不需要用户交互  
  
影响范围（S）：改变  
  
机密性影响（C）：高  
  
完整性影响（l）：高  
  
可用性影响（A）：高  
  
  
  
**网络空间资产测绘**  
  
  
  
  
根据安恒Sumap全球网络空间资产测绘近三个月数据显示，相关资产主要分布在中国、美国和德国等国家，其中国内资产39220。建议客户尽快做好资产排查。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXevmf7xUSbql2tJ0YJMtubAZe1dx9amEM5rWW0nv0YFnAsOcWpo5BBnrPoOOZGVRnE1V01CPzrX9ZQ/640?wx_fmt=png&from=appmsg "")  
  
国内资产分布情况  
  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，受影响的用户建议及时更新至可用的最新版本。  
  
官方支持链接：https://support.atlassian.com/contact/#/  
  
  
  
  
**产品能力覆盖**  
  
  
  
  
目前安恒信息已有9款产品覆盖该漏洞检测与防护。  
  
<table><tbody style="box-sizing:border-box;"><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;background-color:#4577da;box-sizing:border-box;" width="33.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;color:#ffffff;box-sizing:border-box;margin-bottom:unset;"><p><strong style="box-sizing:border-box;">产品名称</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;background-color:#4577da;box-sizing:border-box;" width="67.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;color:#ffffff;box-sizing:border-box;margin-bottom:unset;"><p><strong style="box-sizing:border-box;">覆盖补丁包</strong></p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="33.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>AiLPHA大数据平台</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="67.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>AiNTA-v1.2.5_release_ruletag_1.1.1337</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>AXDR平台的流量探针</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>AiNTA-v1.2.5_release_ruletag_1.1.1337</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>APT攻击预警平台</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>GoldenEyeIPv6_XXXXX_strategy2.0.XXXXX.240120.1</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>明鉴漏洞扫描系统</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>V1.3.1448.1424</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>明鉴远程安全评估系统</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>V1.3.1448.1424</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>云鉴版漏洞扫描系统</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>V1.3.1448.1424</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>WebScan7</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>V1.0.1.137</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>WAF</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>已支持<br/></p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>玄武盾<br/></p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>已支持<br/></p></section></section></td></tr></tbody></table>  
  
  
  
  
**参考资料**  
  
  
  
  
https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html  
  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6777-677获取相关能力支撑。  
  
