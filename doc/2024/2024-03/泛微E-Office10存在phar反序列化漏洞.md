#  泛微E-Office10存在phar反序列化漏洞   
安恒研究院  安恒信息CERT   2024-03-28 20:39  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXesCfIew4xDgxHPaichzoa958OaWgTglXPf5mic3dq7TZc3np7PMDpLQPa4pL89cQvD6FAZaN71atsbA/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody style="box-sizing:border-box;"><tr style="box-sizing:border-box;"><td colspan="4" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;background-color:#4577da;box-sizing:border-box;" width="100.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;color:rgb(255, 255, 255);box-sizing:border-box;margin-bottom:unset;"><p style="text-align:center;"><strong style="box-sizing:border-box;">漏洞概述</strong></p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="75.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">泛微E-Office10存在phar反序列化漏洞</p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;word-break:break-all;">1级</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">10.0（安恒自评）<br/></p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>未分配</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">未分配</p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">未分配</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;word-break:break-all;">WM-202403-000001</p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">已发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">未发现</p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">未发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;">已复现<br/></p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="25.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p style="text-align:left;"><strong style="box-sizing:border-box;">危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="75.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>存在未授权反序列化命令执行漏洞，攻击者可以利用该漏洞获取服务器权限。</p></section></section></td></tr></tbody></table>  
  
安恒研究院卫兵实验室已复现此漏洞。  
  
该产品主要使用客户行业分布广泛，漏洞危害性高，建议客户尽快做好自查及防护。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXeuhI1xQ88p3ibO9yzicoCHBsxpZYaicsVia1YJKiayXjHTl2JYm6a1MhayGbNbLIAia82SsicKar3CBlEmwg/640?wx_fmt=png&from=appmsg "")  
  
泛微E-Office10存在phar反序列化漏洞复现截图  
  
  
  
**漏洞信息**  
  
  
  
  
  
**漏洞描述**  
  
泛微e-office10是一款功能强大的企业办公自动化软件，旨在提升企业的办公效率和管理水平。e-office10提供了一系列全面的办公功能，包括电子公文管理、工作流程设计、协同办公、日程管理、文档管理、会议管理等，满足企业日常办公的各种需求。  
  
**应急响应等级：**  
1级  
  
**漏洞类型：**  
****远程代码执行  
  
**漏洞标签：**  
Web应用  
  
  
**影响范围**  
  
影响版本：  
  
v10.0_20180516 < E-Office < v10.0_20240222  
  
安全版本：  
  
E-Office >= v10.0_20240222  
  
E-Office <= v10.0_20180516  
  
  
**CVSS向量**  
  
访问途径（AV）：网络  
  
攻击复杂度（AC）：低  
  
所需权限（PR）：无需任何权限  
  
用户交互（UI）：不需要用户交互  
  
影响范围 （S）：改变  
  
机密性影响 （C）：高  
  
完整性影响 （l）：高  
  
可用性影响 （A）：高  
  
  
  
**网空资产测绘**  
  
  
  
  
根据安恒Sumap全球网络空间资产测绘数据显示，受影响资产主要分布在中国、新加坡等国家。其中国内资产为1528。建议客户尽快做好资产排查。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXeuhI1xQ88p3ibO9yzicoCHBsxHO3lWubp1WjPWmMHfCcJ9FhnkJBdQyTJqrAB8ib63bK2pYmuglKyjjA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，受影响的用户建议及时下载补丁包进行漏洞修复。  
  
https://service.e-office.cn/knowledge/detail/5  
  
****  
  
  
  
**产品能力覆盖**  
  
  
  
  
<table><tbody style="box-sizing:border-box;"><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;background-color:#4577da;box-sizing:border-box;" width="33.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;color:rgb(255, 255, 255);box-sizing:border-box;margin-bottom:unset;"><p><strong style="box-sizing:border-box;">产品名称</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;background-color:#4577da;box-sizing:border-box;" width="67.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;color:rgb(255, 255, 255);box-sizing:border-box;margin-bottom:unset;"><p><strong style="box-sizing:border-box;">覆盖补丁包</strong></p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="33.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>AiLPHA大数据平台</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="67.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>AiNTA-v1.2.5_release_ruletag_1.1.1377</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>APT攻击预警平台</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>GoldenEyeIPv6_XXXXX_strategy2.0.XXXXX.240328.1</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>明鉴远程安全评估系统</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>V1.3.1516.1526</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>WebScan7</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>V1.0.1.146</p></section></section></td></tr><tr><td width="33.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>WAF</p></section></section></td><td width="67.0000%" style="border-width:1px;border-color:#4577da;border-right-style:solid;border-bottom-style:solid;box-sizing:border-box;"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>已支持</p></section></section></td></tr><tr style="box-sizing:border-box;"><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="33.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>玄武盾</p></section></section></td><td colspan="1" rowspan="1" style="border-width:1px;border-color:#4577da;border-style:solid;box-sizing:border-box;" width="67.0000%"><section style="margin:5px 0%;box-sizing:border-box;"><section style="text-align:left;padding:0px 5px;font-size:14px;box-sizing:border-box;margin-bottom:unset;"><p>已支持</p></section></section></td></tr></tbody></table>  
  
  
  
**参考资料**  
  
  
  
  
https://service.e-office.cn/knowledge/detail/5  
  
https://www.e-office.cn/  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6777-677获取相关能力支撑。  
  
