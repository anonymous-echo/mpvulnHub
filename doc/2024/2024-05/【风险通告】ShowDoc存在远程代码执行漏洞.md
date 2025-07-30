#  【风险通告】ShowDoc存在远程代码执行漏洞   
安恒研究院  安恒信息CERT   2024-05-28 18:30  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXesCfIew4xDgxHPaichzoa958OaWgTglXPf5mic3dq7TZc3np7PMDpLQPa4pL89cQvD6FAZaN71atsbA/640?wx_fmt=png&from=appmsg&wx_&wx_&wx_&wx_ "")  
  
<table><tbody><tr><td colspan="4" rowspan="1" width="100.0000%" data-style="border-width:1px;border-color:rgb(69, 119, 218);border-style:solid;background-color:rgb(69, 119, 218);box-sizing:border-box;" class="js_darkmode__0" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;color: rgb(255, 255, 255);"><p style="text-align:center;"><strong>漏洞概述</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" width="75.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p><span style="letter-spacing:0.544px;">ShowDoc存在远程代码执行漏洞</span></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;word-break:break-all;">1级</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">10.0（安恒自评）</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>未分配</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未分配</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>未分配</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>WM-202405-000003</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现<span style="letter-spacing:0.57834px;line-height:22.4px;"></span></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">分析中</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" width="75.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;overflow: hidden;line-height: 0;"><br/></section><p><span style="font-size:14px;letter-spacing:0.544px;line-height:22.4px;">该漏洞允许攻击者绕过身份验证，利用后台相关接口功能执行代码，执行任意命令，控制服务器。</span></p><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;overflow: hidden;line-height: 0;"><br/></section></section></td></tr></tbody></table>  
  
该产品主要使用客户行业分布广泛，漏洞危害性高，建议客户尽快做好自查及防护。  
  
  
  
**漏洞信息**  
  
  
  
  
  
**产品描述**  
  
ShowDoc是一款简单易用的在线文档编辑与管理工具，旨在帮助团队高效地创建、共享和维护各种类型的文档。  
  
**漏洞危害等级：**  
严重  
  
**漏洞类型：**  
远程代码执行  
  
  
**影响范围**  
  
**影响版本：**  
  
ShowDoc < V3.2.5  
  
  
**CVSS向量**  
  
访问途径（AV）：网络  
  
攻击复杂度（AC）：低  
  
所需权限（PR）：无需任何权限  
  
用户交互（UI）：不需要用户交互  
  
影响范围 （S）：改变  
  
机密性影响 （C）：高  
  
完整性影响 （l）：高  
  
可用性影响 （A）：高  
  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，受影响的用户建议更新至安全版本。  
  
```
https://github.com/star7th/showdoc
```  
  
  
  
  
  
  
**参考资料**  
  
  
  
  
  
```
https://github.com/star7th/showdoc
```  
  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6059-110获取相关能力支撑。  
  
  
