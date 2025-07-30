#  【风险通告】Ivanti Endpoint Manager存在路径穿越敏感信息泄露漏洞   
安恒研究院  安恒信息CERT   2025-01-15 11:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/JAzzLj4nXevmL5H6C1I6nWLYOHeic25ZZq3Sju5Xs1LnOckux8PBqG1qYrBly0Nicx4verjADnLorl5g1ImeuTeg/640?wx_fmt=jpeg&from=appmsg&wx_ "")  
  
<table><tbody><tr><td colspan="4" rowspan="1" data-style="border-width:1px;border-color:rgb(69, 119, 218);border-style:solid;background-color:rgb(69, 119, 218);box-sizing:border-box;" class="js_darkmode__0" style="word-break:break-all;hyphens:auto;border-color:#4577da;background-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;color:#ffffff;box-sizing:border-box;"><p style="text-align:center;"><strong>漏洞概述</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p>Ivanti Endpoint Manager存在路径穿越敏感信息泄露漏洞</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;word-break:break-all;">1级</p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;">9.8<br/></p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><p><span style="font-size:14px;letter-spacing:0.544px;line-height:22.4px;">CVE-2024-10811<br/></span></p><p><span style="font-size:14px;letter-spacing:0.544px;line-height:22.4px;">CVE-2024-13161<br/></span></p><p><span style="font-size:14px;letter-spacing:0.544px;line-height:22.4px;">CVE-2024-13160<br/></span></p><p><span style="font-size:14px;letter-spacing:0.544px;line-height:22.4px;">CVE-2024-13159</span></p><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;overflow:hidden;line-height:0;"><br/></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;">未分配</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p> 未分配</p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p>DM-202411-000375</p><p>DM-202501-000848</p><p>DM-202501-000847</p><p>DM-202501-000846</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p>未发现</p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p>未发现</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p>未发现</p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p>分析中<br/></p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;box-sizing:border-box;"><p style="text-align:left;"><strong>危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" style="word-break:break-all;hyphens:auto;border-color:#4577da;"><section style="margin-top:5px;margin-bottom:5px;"><section style="margin-bottom:unset;padding-right:5px;padding-left:5px;font-size:14px;overflow:hidden;line-height:0;box-sizing:border-box;"><span style="font-size:14px;letter-spacing:0.544px;line-height:22.4px;">未经身份验证的攻击者可以利用绝对路径遍历获取敏感信息，可能导致攻击者获得未经授权的访问、执行远程代码或权限提升等进一步攻击。</span></section></section></td></tr></tbody></table>  
  
该产  
品主要使用客户行业分布广泛，漏洞危害性高，  
建议客户尽快做好自查及防护。  
  
  
  
**漏洞信息**  
  
  
  
  
  
**漏洞描述**  
  
**漏洞危害等级：**  
严重  
  
**漏洞类型：**  
敏感信息泄露  
  
  
**影响范围**  
  
**影响版本：**  
Ivanti Endpoint Manager 2024 <= 2024 November security update  
Ivanti Endpoint Manager 2022 SU6 <= 2024 November security update  
  
**安全版本：**  
  
EPM 2024 January-2025 Patch  
  
EPM 2022 SU6 January-2025 Patch  
  
  
**CVSS向量**  
  
访问途径（AV）：网络  
  
攻击复杂度（AC）：低  
  
所需权限（PR）：无需任何权限  
  
用户交互（UI）：不需要用户交互  
  
影响范围 （S）：不变  
  
机密性影响 （C）：高  
  
完整性影响 （l）：高  
  
可用性影响 （A）：高  
  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，受影响的用户建议及时下载补丁包进行漏洞修复。  
  
1. 下载安全热补丁文件。  
  
EPM 2024补丁下载链接：  
  
https://download.ivanti.com/downloads/Patch/component/EPM2024/Security/Flat/EPM_2024_Flat_Jan_2025_Patch.zip  
  
EPM 2022 SU6补丁下载链接：  
  
https://download.ivanti.com/downloads/Patch/component/EPM2022/Security/SU6/EPM_2022_SU6_Jan_2025_Patch.zip  
  
2. 关闭EPM控制台。  
  
3. 解压文件夹，以管理员身份打开PowerShell，然后运行Deploy.ps1（zip文件中包含详细说明）。  
  
4. 重新启动。  
  
**参考资料**  
  
  
  
  
https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6?language=en_US  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6059-110获取相关能力支撑。  
  
