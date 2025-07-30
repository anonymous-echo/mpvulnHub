#  【已复现】Microsoft Exchange Server "OWASSRF" 漏洞安全风险通告   
 代码卫士   2022-12-26 17:38  
  
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
  
  
  
Microsoft Exchange Server是微软公司的一套电子邮件服务组件。  
除传统的电子邮件的存取、储存、转发功能外，在新版本的产品中亦加入了一系列辅助功能，如语音邮件、邮件过滤筛选和OWA（基于Web的电子邮件存取）。  
  
  
近日，奇安信CERT监测到CrowdStrike发布针对Microsoft Exchange Server新的利用链的技术细节，并将其命名为**"OWASSRF"**，其中涉及两个漏洞：  
  
**Microsoft Exchange Server权限提升漏洞(CVE-2022-41080)**  
：经过身份认证的远程攻击者可通过Outlook Web Application (OWA)端点获得在系统上下文中执行PowerShell的权限。  
  
**Microsoft Exchange Server远程代码执行漏洞(CVE-2022-41082)**  
：具有执行PowerShell权限的远程攻击者可利用此漏洞在目标系统上执行任意代码。  
  
  
组合这两个漏洞，经过身份认证的远程攻击者可通过Outlook Web Application (OWA)端点最终执行任意代码。值得注意的是，**"OWASSRF"漏洞利用链绕过了之前Microsoft为"ProxyNotShell"提供的缓解措施。目前监测到POC及EXP已在互联网上公开，同时已发现在野利用。鉴于此漏洞利用链影响较大，建议客户尽快做好自查及防护。**  
  
****  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="63"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="3" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;padding: 0px 7px;" height="25"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>Microsoft Exchange Server </strong><strong>权限提升漏洞</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="78"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>公开时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="159"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2022-11-08</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="123"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>更新时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="172"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2022-12-23</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="91"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="166"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2022-41080</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="130"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="174"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2022-43833</span></p><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CNNVD-202211-2376</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="99"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>威胁类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="166"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">权限提升</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="133"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="172"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">服务端请求伪造</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="105"><p><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>厂商</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="163"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="134"><p><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>产品</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="170"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Exchange Server</span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>奇安信</strong><strong>CERT</strong><strong>风险评级</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: rgb(0, 112, 192);">蓝色（一般事件）</span></strong></span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>现时威胁状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="109"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>POC</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="162"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>EXP</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="134"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>在野利用状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="169"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术细节状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="112"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已发现</span></strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="161"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已发现</span></strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="133"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已发现</span></strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="168"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已公开</span></strong></span></p></td></tr><tr style="height:104px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="104" width="114"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞描述</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="104"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server中存在权限提升漏洞，该漏洞允许经过身份认证的远程攻击者通过Outlook Web Application (OWA)端点获得在系统上下文中执行PowerShell的权限。</span></p></td></tr><tr style="height:61px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="61" width="116"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响版本</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="61"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2016 Cumulative Update 22<br/>Microsoft Exchange Server 2019 Cumulative Update 11<br/>Microsoft Exchange Server 2013 Cumulative Update 23<br/>Microsoft Exchange Server 2019 Cumulative Update 12<br/>Microsoft Exchange Server 2016 Cumulative Update 23</span></p></td></tr><tr style="height:110px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="110" width="117"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他受影响组件</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="110"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">无</span></p></td></tr></tbody></table>  
  
目前，奇安信CERT已成功复现**Microsoft Exchange Server "OWASSRF"漏洞**，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icOJhhRuXCZ9xX0CvvOVE5Kfqot1HFicVFZfu3Tsf0qNuUgsB8TI7kUXac7SyBFHYSamFtAcdC0Huw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icOJhhRuXCZ9xX0CvvOVE5KSFKLZqYkrKPRZSREmqf2loMSoz1bj78T51Wu210wll51MCskOiawCgw/640?wx_fmt=png "")  
  
  
威胁评估  
  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="64"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="4" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;padding: 0px 7px;" height="25" width="56"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>Microsoft Exchange Server </strong><strong>权限提升漏洞</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="64"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="107"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2022-41080</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="114"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2022-43833</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="64"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>评级</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="107"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="167"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>分数</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="114"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">8.8</span></p></td></tr><tr style="height:25px;"><td rowspan="8" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="64"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS</strong><strong>向量</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="56"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>访问途径（</strong><strong>AV</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>攻击复杂度（</strong><strong>AC</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">网络</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>所需权限（</strong><strong>PR</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>用户交互（</strong><strong>UI</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低权限</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">不需要</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响范围（</strong><strong>S</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>机密性影响（</strong><strong>C</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">不改变</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>完整性影响（</strong><strong>I</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>可用性影响（</strong><strong>A</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="279"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="173"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:160px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="160" width="64"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>危害描述</strong></span></p></td><td colspan="4" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="160" width="56"><p style="line-height:150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">经过身份认证的远程攻击者可利用此漏洞获得在系统上下文中执行PowerShell的权限，配合<span style="line-height: 150%;">CVE-2022-41082漏洞最终可在目标服务器上执行任意代码。</span></span></p></td></tr></tbody></table>  
  
处置建议  
  
**微软已于11月发布此漏洞受影响版本的安全补丁，强烈建议受影响的用户尽快安装安全补丁进行防护。建议受影响用户通过以下链接进行手动更新：**  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41080  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082****  
  
  
**缓解措施：**  
  
1、若暂时无法应用补丁，建议禁用OWA来缓解此漏洞  
  
2、禁止非管理员用户使用远程PowerShell访问  
  
关于如何禁用单用户或多用户远程PoweShell访问可参考以下链接：  
  
https://learn.microsoft.com/en-us/powershell/exchange/control-remote-powershell-access-to-exchange-servers  
  
3、确保X-Forwarded-For HTTP请求头记录真实的外部IP地址  
  
  
另外，CrowdStrike已开发脚本用于监视IIS及Powershell日志：https://github.com/CrowdStrike/OWASSRF  
  
  
产品解决方案  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全面支持对Exchange SSRF漏洞(CVE-2022-41080)的防护。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7688，建议用户尽快升级检测规则库至2212221600以上。  
  
  
**奇安信天眼检测方案**  
  
奇安信天眼新一代安全感知系统已经能够有效检测针对该漏洞的攻击，请将规则版本升级到3.0.1223.13685或以上版本。规则ID及规则名称：  
  
0x10021419，Microsoft Exchange 服务端请求伪造漏洞(CVE-2022-41080)。奇安信天眼流量探针规则升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**奇安信自动化渗透测试系统产品解决方案**  
  
奇安信自动化渗透测试系统在第一时间加入了该漏洞的插件规则和指纹规则，请将插件版本和指纹版本升级到20221223180110版本。规则名称：Microsoft Exchange CVE-2022-41080 服务端请求伪造漏洞，插件版本：20221223180110，指纹版本：20221223180110。奇安信自动化渗透测试系统升级方法：系统管理->升级管理->插件升级（指纹升级），选择“网络升级”或“本地升级”。  
  
  
参考资料  
  
[1]https://unit42.paloaltonetworks.com/threat-brief-OWASSRF/  
  
[2]https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41080  
  
[3]https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082  
  
[4]https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/  
  
  
时间线  
  
2022年12月14日，  
奇安信 CERT发布安全风险通告。  
  
  
点击**阅读原文**  
到奇安信NOX-安全监测平台查询更多漏洞详情  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
  
