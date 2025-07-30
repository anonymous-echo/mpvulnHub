#  【已复现】泛微 E-COLOGY存在SQL注入漏洞   
安恒研究院  安恒信息CERT   2024-07-15 18:18  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXesCfIew4xDgxHPaichzoa958OaWgTglXPf5mic3dq7TZc3np7PMDpLQPa4pL89cQvD6FAZaN71atsbA/640?wx_fmt=png&from=appmsg&wx_&wx_&wx_ "")  
  
<table><tbody><tr><td colspan="4" rowspan="1" style="border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);" width="100.0000%" data-style="border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);" class="js_darkmode__0"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;color:rgb(255, 255, 255);margin-bottom:unset;box-sizing:border-box;"><p style="text-align:center;"><strong>漏洞概述</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" style="border-color:rgb(69, 119, 218);" width="75.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;">泛微 E-COLOGY存在SQL注入漏洞</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;word-break:break-all;">1级</p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;">9.8（安恒自评）<br/></p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;word-break:break-all;">未分配<br/></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;">未分配</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>未分配</p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>WM-202407-000002</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>已发现</p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;">未发现</p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>已发现</p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;">已复现<br/></p></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color:rgb(69, 119, 218);" width="25.0000%"><section style="margin:5px 0%;"><section style="padding-right:5px;padding-left:5px;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p style="text-align:left;"><strong>危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" style="border-color:rgb(69, 119, 218);" width="75.0000%"><p><span style="font-size:14px;letter-spacing:0.57834px;line-height:22.4px;">远程未授权攻击者可利用此漏洞获取敏感信息，进一步利用可能获取目标系统权限。</span></p></td></tr></tbody></table>  
  
该产品主要使用客户行业分布广泛，漏洞危害性高，建议客户尽快做好自查及防护。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXeudDHURpO4t7fszOJoibB2yibrv2NSPicBgumtq9R8aAXSV6gZEcUPHHBbMEyXNLECbleiciazqSCLmViaQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**漏洞信息**  
  
  
  
  
**产品描述**  
  
泛微E-COLOGY是一款由中国泛微软件系统股份有限公司开发的企业协同管理软件，为中大型组织创建全新的高效协同办公环境，智能语音办公，简化软件操作界面、身份认证、电子签名、电子签章、数据存证让合同全程数字化。  
  
  
**漏洞危害等级：**  
严重  
  
**漏洞类型：**  
SQL注入  
  
  
**影响范围**  
  
影响版本：  
  
version < 10.64.1  
  
安全版本：  
  
version >= 10.64.1  
  
  
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
  
```
https://www.weaver.com.cn/cs/securityDownload.html?src=cn
```  
  
  
  
  
**产品能力覆盖**  
  
  
  
<table><tbody><tr><td colspan="1" rowspan="1" width="33.0000%" style="border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);" data-style="border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);" class="js_darkmode__29"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;color:rgb(255, 255, 255);margin-bottom:unset;box-sizing:border-box;"><p><strong>产品名称</strong></p></section></section></td><td colspan="1" rowspan="1" width="67.0000%" style="border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);" data-style="border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);" class="js_darkmode__30"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;color:rgb(255, 255, 255);margin-bottom:unset;box-sizing:border-box;"><p><strong>覆盖补丁包</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="33.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>AiLPHA大数据平台</p></section></section></td><td colspan="1" rowspan="1" width="67.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>GoldenEyeIPv6_XXXXX_strategy2.0.XXXXX.240715.1及以上版本</p></section></section></td></tr><tr><td width="33.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>APT攻击预警平台</p></section></section></td><td width="67.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>GoldenEyeIPv6_XXXXX_strategy2.0.XXXXX.240715.1及以上版本</p></section></section></td></tr><tr><td width="33.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>明鉴漏洞扫描系统</p></section></section></td><td width="67.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>V1.3.1759.1656及以上版本<br/></p></section></section></td></tr><tr><td width="33.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>WAF</p></section></section></td><td width="67.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>已支持</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="33.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>玄武盾</p></section></section></td><td colspan="1" rowspan="1" width="67.0000%" style="border-color:rgb(69, 119, 218);"><section style="margin-top:5px;margin-bottom:5px;"><section style="padding-right:5px;padding-left:5px;text-align:left;font-size:14px;margin-bottom:unset;box-sizing:border-box;"><p>已支持</p></section></section></td></tr></tbody></table>  
  
  
  
**参考资料**  
  
  
  
  
```
https://www.weaver.com.cn/cs/securityDownload.html?src=cn
```  
  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6059-110获取相关能力支撑。  
  
