#  【已复现】Atlassian Jira 多款产品Mobile Plugin服务端请求伪造漏洞安全风险通告   
原创 QAX CERT  奇安信 CERT   2022-07-06 17:19  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icrhoWdKnhTgicSjB9pXdeZwDibNIBAEMegibEdG1vrjOibsq887TUz3ztMkM6Qvibic7r26sqbUIbicOMYg/640?wx_fmt=png "https://image.ipaiban.com/upload-ueditor-image-20201112-1605175807303084927.png")  
  
奇安信CERT  
  
**致力于**  
第一时间  
为企业级用户提供安全风险  
**通告**  
和  
**有效**  
解决方案。  
  
  
**安全通告**  
  
  
  
近日，奇安信CERT监测到Atlassian Jira 多款产品 Mobile Plugin 服务端请求伪造漏洞PoC及细节在互联网上公开，经过身份验证的远程攻击者可通过Jira Core REST API伪造服务端发送特制请求，从而导致服务端敏感信息泄露，同时为下一步攻击利用提供条件。**鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
<table><tbody><tr><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="54"><p><span style="font-size: 14px;"><strong>漏洞名称</strong></span></p></td><td colspan="3" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;"><strong>Atlassian Jira 多款产品 Mobile Plugin 服务端请求伪造漏洞</strong></span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="75"><p><span style="font-size: 14px;"><strong>公开时间</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="169"><p><span style="font-size: 14px;">2022-06-26</span></p></td><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="130"><p><span style="font-size: 14px;"><strong>更新时间</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="140"><p><span style="font-size: 14px;">2022-07-06</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="93"><p><span style="font-size: 14px;"><strong>CVE编号</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="177"><p><span style="font-size: 14px;">CVE-2022-26135</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="140"><p><span style="font-size: 14px;"><strong>其他编号</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="146"><p><span style="font-size: 14px;">QVD-2022-10217</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="104"><p><span style="font-size: 14px;"><strong>威胁类型</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="174"><p><span style="font-size: 14px;">信息泄露</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="143"><p><span style="font-size: 14px;"><strong>技术类型</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="147"><p><span style="font-size: 14px;">服务端请求伪造</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="111"><p><span style="font-size: 14px;"><strong>厂商</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="171"><p><span style="font-size: 14px;">Atlassian</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="143"><p><span style="font-size: 14px;"><strong>产品</strong></span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="146"><p><span style="font-size: 14px;">Jira Server</span></p></td></tr><tr><td colspan="4" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;"><strong>风险等级</strong></span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;"><strong>奇安信CERT风险评级</strong></span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;"><strong>风险等级</strong></span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;color: rgb(255, 0, 0);"><strong>高危</strong></span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;color: rgb(12, 118, 240);"><strong>蓝色（一般事件）</strong></span></p></td></tr><tr><td colspan="4" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;"><strong>现时威胁状态</strong></span></p></td></tr><tr><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="116"><p><span style="font-size: 14px;"><strong>POC状态</strong></span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="170"><p><span style="font-size: 14px;"><strong>EXP状态</strong></span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="142"><p><span style="font-size: 14px;"><strong>在野利用状态</strong></span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="145"><p><span style="font-size: 14px;"><strong>技术细节状态</strong></span></p></td></tr><tr><td align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="120"><p><span style="font-size: 14px;color: rgb(255, 0, 0);"><strong>已发现</strong></span></p></td><td align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="169"><p><span style="font-size: 14px;color: rgb(255, 0, 0);"><strong>已发现</strong></span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="141"><p><span style="font-size: 14px;">未发现</span></p></td><td align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="144"><p><span style="font-size: 14px;color: rgb(255, 0, 0);"><strong>已公开</strong></span></p></td></tr><tr><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="122"><p><span style="font-size: 14px;"><strong>漏洞描述</strong></span></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Atlassian Jira 多款产品 Mobile Plugin中存在服务端请求伪造漏洞(SSRF)，经过身份验证的远程攻击者可通过向Jira Core REST API发送特制请求，从而伪造服务端发起请求，从而导致敏感信息泄露，同时为下一步攻击利用提供条件。需注意的是，若服务端开启注册功能，则未授权用户可通过注册获取权限进而利用。</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="124"><p><span style="font-size: 14px;"><strong>影响版本</strong></span></p></td><td colspan="3" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Jira Core Server/Jira Software Server/</span><span style="font-size: 14px;">Jira Software Data Center:</span></p><section data-role="list"><ul class="list-paddingleft-1" style="list-style-type: disc;margin: 0px;padding: 0px 0px 0px 30px;"><li><p><span style="font-size: 14px;">8.0 &lt; 8.13.22</span></p></li><li><p><span style="font-size: 14px;">8.14.x</span></p></li><li><p><span style="font-size: 14px;">8.15.x</span></p></li><li><p><span style="font-size: 14px;">8.16.x</span></p></li><li><p><span style="font-size: 14px;">8.17.x</span></p></li><li><p><span style="font-size: 14px;">8.18.x</span></p></li><li><p><span style="font-size: 14px;">8.19.x</span></p></li><li><p><span style="font-size: 14px;">8.20.x &lt; 8.20.10</span></p></li><li><p><span style="font-size: 14px;">8.21.x</span></p></li><li><p><span style="font-size: 14px;">8.22.x &lt; 8.22.4</span></p></li></ul></section><p><span style="font-size: 14px;">Jira Service Management Server/Data Center:</span></p><section data-role="list"><ul class="list-paddingleft-1" style="list-style-type: disc;margin: 0px;padding: 0px 0px 0px 30px;"><li><p><span style="font-size: 14px;">4.0 &lt; 4.13.22</span></p></li><li><p><span style="font-size: 14px;">4.14.x</span></p></li><li><p><span style="font-size: 14px;">4.15.x</span></p></li><li><p><span style="font-size: 14px;">4.16.x</span></p></li><li><p><span style="font-size: 14px;">4.17.x</span></p></li><li><p><span style="font-size: 14px;">4.18.x</span></p></li><li><p><span style="font-size: 14px;">4.19.x</span></p></li><li><p><span style="font-size: 14px;">4.20.x &lt; 4.20.10</span></p></li><li><p><span style="font-size: 14px;">4.21.x</span></p></li><li><p><span style="font-size: 14px;">4.22.x &lt; 4.22.4</span></p></li></ul></section></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="125"><p><span style="font-size: 14px;"><strong>不受影响版本</strong></span></p></td><td colspan="3" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Jira Core Server/Jira Software Server/</span><span style="font-size: 14px;">Jira Software Data Center:</span></p><section data-role="list"><ul class="list-paddingleft-1" style="list-style-type: disc;margin: 0px;padding: 0px 0px 0px 30px;"><li><p><span style="font-size: 14px;">8.13.x &gt;= 8.13.22</span></p></li><li><p><span style="font-size: 14px;">8.20.x &gt;= 8.20.10</span></p></li><li><p><span style="font-size: 14px;">8.22.x &gt;= 8.22.4</span></p></li><li><p><span style="font-size: 14px;">9.0.0</span></p></li></ul></section><p><span style="font-size: 14px;">Jira Service Management Server and Data Center:</span></p><section data-role="list"><ul class="list-paddingleft-1" style="list-style-type: disc;margin: 0px;padding: 0px 0px 0px 30px;"><li><p><span style="font-size: 14px;">4.13.x &gt;= 4.13.22</span></p></li><li><p><span style="font-size: 14px;">4.20.x &gt;= 4.20.10</span></p></li><li><p><span style="font-size: 14px;">4.22.x &gt;= 4.22.4</span></p></li><li><p><span style="font-size: 14px;">5.0.0</span></p></li></ul></section></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="125"><p><span style="font-size: 14px;"><strong>其他受影响组件</strong></span></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">无</span></p></td></tr></tbody></table>  
  
目前，奇安信CERT已成功复现**Atlassian Jira 多款产品 Mobile Plugin 服务端请求伪造漏洞(CVE-2022-26135)**，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icDVLDHtAicJGFqXQYX4J4l0JYnrEnoSMO8S9JCr5tgop4dSXuibJrRcnlzxVu3fV8MzTP9zDt0HqOw/640?wx_fmt=png "")  
  
  
威胁评估  
  
<table><tbody><tr><td style="word-break: break-all;padding: 5px 10px;" width="36"><p><strong><span style="font-size: 14px;">漏洞名称</span></strong></p></td><td colspan="4" style="padding: 5px 10px;" width="449"><p><span style="font-size: 14px;">Atlassian Jira多款产品Mobile Plugin服务端请求伪造漏洞</span></p></td></tr><tr><td style="padding: 5px 10px;" width="86"><p><strong><span style="font-size: 14px;">CVE编号</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;" width="98"><p><span style="font-size: 14px;">CVE-2022-26135</span></p></td><td colspan="2" style="word-break: break-all;padding: 5px 10px;" width="207"><p><strong><span style="font-size: 14px;">其他编号</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;" width="102"><p><span style="font-size: 14px;">QVD-2022-10217</span></p></td></tr><tr><td style="padding: 5px 10px;" width="36"><p><strong><span style="font-size: 14px;">CVSS 3.1评级</span></strong></p></td><td align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="98"><p><span style="color: rgb(255, 0, 0);"><strong><span style="color: rgb(255, 0, 0);font-size: 14px;">高危</span></strong></span></p></td><td colspan="2" style="padding: 5px 10px;" width="207"><p><strong><span style="font-size: 14px;">CVSS 3.1分数</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;" width="102"><p><span style="font-size: 14px;">8.5</span></p></td></tr><tr><td rowspan="8" style="padding: 5px 10px;" width="36"><p><strong><span style="font-size: 14px;">CVSS向量</span></strong></p></td><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="302"><p><strong><span style="font-size: 14px;">访问途径（AV）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;"><p><strong><span style="font-size: 14px;">攻击复杂度（AC）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="323"><p><span style="font-size: 14px;">网络</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><span style="font-size: 14px;">低</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="330"><p><strong><span style="font-size: 14px;">所需权限（PR）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><strong><span style="font-size: 14px;">用户交互（UI）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="333"><p><span style="font-size: 14px;">低权限</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><span style="font-size: 14px;">不需要</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="334"><p><strong><span style="font-size: 14px;">影响范围（S）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><strong><span style="font-size: 14px;">机密性影响（C）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="334"><p><span style="font-size: 14px;">改变</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><span style="font-size: 14px;">高</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="334"><p><strong><span style="font-size: 14px;">完整性影响（I）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><strong><span style="font-size: 14px;">可用性影响（A）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="334"><p><span style="font-size: 14px;">低</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="35"><p><span style="font-size: 14px;">无</span></p></td></tr><tr><td style="padding: 5px 10px;" width="36"><p><strong><span style="font-size: 14px;">危害描述</span></strong></p></td><td colspan="4" style="padding: 5px 10px;" width="449"><p><span style="font-size: 14px;">经过身份验证的远程攻击者可通过Jira Core REST API伪造服务端发送特制请求，从而导致服务端敏感信息泄露，同时为下一步攻击利用提供条件。</span></p></td></tr></tbody></table>  
  
处置建议  
  
**1. 升级到最新版本:**  
  
Jira Core Server、Jira Software Server 和 Jira Software Data Center 可升级至：  
- 8.13.22  
  
- 8.20.10  
  
- 8.22.4   
  
- 9.0.0  
  
Jira Service Management Server 和Data Center可升级至：  
- 4.13.22  
  
- 4.20.10  
  
- 4.22.4   
  
- 5.0.0  
  
**2. 缓解措施:**  
  
(1)	 关闭用户注册功能  
  
(2)	 禁用Mobile Plugin  
  
1、在应用程序的顶部导航栏中，选择**设置 -> 管理加载项或管理应用程序**  
  
2、找到Mobile Plugin for Jira Data Center and Server应用程序，然后选择**禁用**即可。   
  
(3) 升级Mobile Plugin至最新版本  
  
  
更多详情请参见：  
  
https://confluence.atlassian.com/jira/jira-server-security-advisory-29nd-june-2022-1142430667.html  
  
  
产品解决方案  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全面支持对Jira多个产品服务端请求伪造漏洞(CVE-2022-26135)的防护。  
  
  
**奇安信天眼产品解决方案**  
  
奇安信天眼新一代威胁感知系统在第一时间加入了该漏洞的检测规则，请将规则包升级到3.0.0706.13422上版本。规则名称：Atlassian Jira多个产品服务端请求伪造漏洞(CVE-2022-26135)，规则ID：0x10020FC7。奇安信天眼流量探针（传感器）升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
参考资料  
  
[1]  
https://confluence.atlassian.com/jira/jira-server-security-advisory-29nd-june-2022-1142430667.html  
  
  
时间线  
  
2022年7月6日，奇安信 CERT发布安全风险通告。  
  
  
点击**阅读原文**  
到奇安信NOX-安全监测平台查询更多漏洞详情  
