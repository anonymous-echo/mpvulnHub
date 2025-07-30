#  Atlassian Confluence Data Center and Server存在远程代码执行漏洞   
安恒研究院  安恒信息CERT   2024-05-22 18:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXesCfIew4xDgxHPaichzoa958OaWgTglXPf5mic3dq7TZc3np7PMDpLQPa4pL89cQvD6FAZaN71atsbA/640?wx_fmt=png&from=appmsg&wx_&wx_&wx_&wx_ "")  
  
<table><tbody><tr><td colspan="4" rowspan="1" width="100.0000%" data-style="border-width:1px;border-color:rgb(69, 119, 218);border-style:solid;background-color:rgb(69, 119, 218);box-sizing:border-box;" class="js_darkmode__0" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;color: rgb(255, 255, 255);"><p style="text-align:center;"><strong>漏洞概述</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" width="75.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><span style="letter-spacing:0.544px;text-align:justify;">Atlassian Confluence Data Center and Server存在远程代码执行漏洞</span><span style="letter-spacing:0.544px;text-align:justify;">(CVE-2024-21683)</span></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;word-break:break-all;">2级</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">8.8（安恒自评）</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>CVE-2024-21683</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未分配</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>未分配</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>DM-202401-000015</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发<span style="letter-spacing:0.57834px;line-height:22.4px;">现</span></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">分析中</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" width="75.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;overflow: hidden;line-height: 0;"><br/></section><p><span style="font-size:14px;letter-spacing:0.57834px;">允许经过身份验证的攻击者执行对机密性、完整性、可用性有高影响且无需用户交互的任意代码。</span></p><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;overflow: hidden;line-height: 0;"><br/></section></section></td></tr></tbody></table>  
  
该产品主要使用客户行业分布广泛，漏洞危害性高，建议客户尽快做好自查及防护。  
  
  
  
**漏洞信息**  
  
  
  
  
  
**产品描述**  
  
Atlassian Confluence 是一款专为团队合作设计的内容协作软件。它使团队能够共同创建、分享和协作编辑文档，从而有效地管理项目知识和信息。Confluence 还集成了多种宏和插件，如日程表、任务列表和Jira集成。  
  
**漏洞危害等级：**  
高危  
  
**漏洞类型：**  
远程代码执行  
  
  
**影响范围**  
  
**影响版本：**  
  
Atlassian Data Center = 8.9.0  
  
8.8.0 <= Atlassian Data Center <= 8.8.1  
  
8.7.0 <= Atlassian Data Center <= 8.7.2  
  
8.6.0 <= Atlassian Data Center <= 8.6.2  
  
8.5.0 <= Atlassian Data Center and Server <= 8.5.8 LTS  
  
8.4.0 <= Atlassian Data Center and Server <= 8.4.5  
  
8.3.0 <= Atlassian Data Center and Server <= 8.3.4  
  
8.2.0 <= Atlassian Data Center and Server <= 8.2.3  
  
8.1.0 <= Atlassian Data Center and Server <= 8.1.4  
  
8.0.0 <= Atlassian Data Center and Server <= 8.0.4  
  
7.20.0 <= Atlassian Data Center and Server <= 7.20.3  
  
7.19.0 <= Atlassian Data Center and Server <= 7.19.21 LTS  
  
7.18.0 <= Atlassia  
n Data Center and   
Server <= 7.18.3  
  
7.17.0 <= Atlassian Data Center and Server <= 7.17.5  
  
**安全版本：**  
  
Atlassian Data Center >= 8.9.1  
  
Atlassian Data Center >= 8.9.1 or 8.5.9 LTS recommended  
  
Atlassian Data Center >= 7.19.22 LTS  
  
Atlassian Server >= 8.5.9 LTS recommended  
  
Atlassian Server >= 7.19.22 LTS  
  
  
**CVSS向量**  
  
访问途径（AV）：网络  
  
攻击复杂度（AC）：低  
  
所需权限（PR）：低  
  
用户交互（UI）：不需要用户交互  
  
影响范围 （S）：改变  
  
机密性影响 （C）：高  
  
完整性影响 （l）：高  
  
可用性影响 （A）：高  
  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，受影响的用户建议更新至安全版本。  
  
  
官方链接：  
  
```
https://www.atlassian.com/software/confluence/download-archives
```  
  
  
  
  
  
**网空资产测绘**  
  
  
  
  
根据安恒Sumap全球网络空间资产测绘近三个月数据显示，受影响资产主要分布在美国、日本和德国等国家，其中国内资产为3264。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXevwQmZrx3ia8cbOogqsOyXY9qYg2tbzPIcZzNa1pSvysFlwwjWkMlF7Ndz9CTclKPKaibdeQGS9icdcg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**参考资料**  
  
  
  
  
  
```
https://confluence.atlassian.com/security/security-bulletin-may-21-2024-1387867145.html
https://jira.atlassian.com/browse/CONFSERVER-95832
```  
  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6059-110获取相关能力支撑。  
  
