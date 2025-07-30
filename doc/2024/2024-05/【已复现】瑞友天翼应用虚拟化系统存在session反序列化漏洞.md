#  【已复现】瑞友天翼应用虚拟化系统存在session反序列化漏洞   
安恒研究院  安恒信息CERT   2024-05-11 18:32  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXesCfIew4xDgxHPaichzoa958OaWgTglXPf5mic3dq7TZc3np7PMDpLQPa4pL89cQvD6FAZaN71atsbA/640?wx_fmt=png&from=appmsg&wx_&wx_&wx_ "")  
  
<table><tbody><tr><td colspan="4" rowspan="1" width="100.0000%" data-style="border-width:1px;border-color:rgb(69, 119, 218);border-style:solid;background-color:rgb(69, 119, 218);box-sizing:border-box;" class="js_darkmode__0" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;color: rgb(255, 255, 255);"><p style="text-align:center;"><strong>漏洞概述</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>漏洞名称</strong></p></section></section></td><td colspan="3" rowspan="1" width="75.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">瑞友天翼应用虚拟化系统session反序列化漏洞</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>安恒CERT评级</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;word-break:break-all;">1级</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CVSS3.1评分</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">10.0(安恒自评)<br/></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CVE编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;word-break:break-all;">未分配</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未分配</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>CNNVD编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>未分配<br/></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>安恒CERT编号</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p>WM-202405-000002</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>POC情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">已发<span style="letter-spacing:0.57834px;line-height:22.4px;">现</span></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>EXP情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">未发现</p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>研究情况</strong></p></section></section></td><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;">已复现</p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="25.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;"><p style="text-align:left;"><strong>危害描述</strong></p></section></section></td><td colspan="3" rowspan="1" width="75.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;overflow: hidden;line-height: 0;"><br/></section><p><span style="font-size:14px;letter-spacing:0.57834px;">攻击者可以通过该漏洞构造恶意数据包实现数据的反序列化，导致服务器敏感数据泄露。</span></p><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;font-size: 14px;overflow: hidden;line-height: 0;"><br/></section></section></td></tr></tbody></table>  
  
安恒研究院卫兵实验室已复现此漏洞。  
  
该产品主要使用客户行业分布广泛，漏洞危害性高，建议客户尽快做好自查及防护。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JAzzLj4nXeuy5yFFjYuu618tHMAEgaAnrFtcOf7viaD9Ufg0xFPYf7BaWDLaaYXgFITtu2Ed5PibcuhFRKV1icfEw/640?wx_fmt=png&from=appmsg "")  
  
瑞友天翼应用虚拟化系统session反序列化漏洞复现截图  
  
  
  
**漏洞信息**  
  
  
  
  
  
**产品描述**  
  
瑞友天翼应用虚拟化系统是西安瑞友信息技术资讯有限公司研发的具有自主知识产权，基于服务器计算(Server-based Computing)架构的应用虚拟化平台。  
  
**漏洞危害等级：**  
严重  
  
**漏洞类型：**  
反序列化  
  
  
**影响范围**  
  
影响  
版本：  
  
瑞友天翼应用虚拟化系统 <   
GWT7.0.5_patch_202405081139  
  
  
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
  
  
  
  
根据安恒Sumap全球网络空间资产测绘近三个月数据显示，受影响资产主要分布在中国、菲律宾和印度尼西亚等国家，其中国内资产为13635。建议客户尽快做好资产排查。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/JAzzLj4nXeuy5yFFjYuu618tHMAEgaAnUobY5Zb2EhDMfsy99JmbIc1sIKUsWwVHnO47bovfmtTY2iaEbfTeEzg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，受影响的用户建议及时下载补丁包进行漏洞修复。  
  
  
  
**产品能力覆盖**  
  
  
  
<table><tbody><tr><td colspan="1" rowspan="1" width="33.0000%" data-style="border-width:1px;border-color:rgb(69, 119, 218);border-style:solid;background-color:rgb(69, 119, 218);box-sizing:border-box;" class="js_darkmode__38" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;color: rgb(255, 255, 255);"><p><strong>产品名称</strong></p></section></section></td><td colspan="1" rowspan="1" width="67.0000%" data-style="border-width:1px;border-color:rgb(69, 119, 218);border-style:solid;background-color:rgb(69, 119, 218);box-sizing:border-box;" class="js_darkmode__39" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);background-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;color: rgb(255, 255, 255);"><p><strong>覆盖补丁包</strong></p></section></section></td></tr><tr><td colspan="1" rowspan="1" width="33.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>AiLPHA大数据平台</p></section></section></td><td colspan="1" rowspan="1" width="67.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>AiNTA-v1.2.5_release_ruletag_1.1.1416及以上版本</p></section></section></td></tr><tr><td width="33.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>APT攻击预警平台</p></section></section></td><td width="67.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>GoldenEyeIPv6_XXXXX_strategy2.0.XXXXX.240511.1及以上版本</p></section></section></td></tr><tr><td width="33.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>明鉴漏洞扫描系统</p></section></section></td><td width="67.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>V1.3.1625.1597及以上版本</p></section></section></td></tr><tr><td width="33.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p><span style="letter-spacing: 0.544px;">WebScan7</span></p></section></section></td><td width="67.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>v1.0.1.155及以上版本</p></section></section></td></tr><tr><td width="33.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>WAF<br/></p></section></section></td><td width="67.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>已支持<br/></p></section></section></td></tr><tr><td width="33.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>玄武盾<br/></p></section></section></td><td width="67.0000%" style="word-break:break-all;hyphens:auto;border-color:rgb(69, 119, 218);"><section style="margin-top: 5px;margin-bottom: 5px;"><section style="margin-bottom: unset;padding-right: 5px;padding-left: 5px;text-align: left;font-size: 14px;"><p>已支持<br/></p></section></section></td></tr></tbody></table>  
  
  
  
**参考资料**  
  
  
  
  
  
```
http://www.realor.cn
```  
  
  
  
  
**技术支持**  
  
  
  
  
如有漏洞相关需求支持请联系400-6059-110获取相关能力支撑。  
  
