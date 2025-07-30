#  Microsoft Exchange Server多个0Day漏洞安全风险通告第六次更新   
原创 QAX CERT  奇安信 CERT   2022-11-09 14:35  
  
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
  
  
  
近日，奇安信CERT监测到GTSC SOC 团队发布博客，披露了Microsoft Exchange Server中的两个0Day漏洞，包括：Microsoft Exchange Server权限提升漏洞(CVE-2022-41040)和Microsoft Exchange Server远程代码执行漏洞(CVE-2022-41082)。经过身份验证的远程攻击者可使用相关漏洞利用链在目标系统上执行任意代码。**目前，这两个漏洞已被检测到在野利用。鉴于这些漏洞影响较大，微软官方已发布安全补丁，奇安信CERT强烈建议客户尽快修复漏洞。**  
  
****  
**本次更新内容：**  
  
**监测到微软发布安全补丁，更新处置建议。**  
  
****  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="68"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="3" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;padding: 0px 7px;" height="25" width="475"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>Microsoft Exchange Server</strong><strong>权限提升漏洞</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="68"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>公开时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="156"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2022-09-30</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="132"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>更新时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="155"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2022-10-01</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="68"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="156"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2022-41040</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="139"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="159"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2022-26556</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="68"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>威胁类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="156"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">权限提升</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="141"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="158"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">服务端请求伪造</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="68"><p><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>厂商</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="154"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="141"><p><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>产品</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="157"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Exchange Server</span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>奇安信</strong><strong>CERT</strong><strong>风险评级</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: rgb(0, 112, 192);">蓝色（一般事件）</span></strong></span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>现时威胁状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="68"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>POC</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="154"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>EXP</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="140"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>在野利用状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="156"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术细节状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="68"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="154"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="139"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已发现</span></strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="155"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr style="height:104px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="104" width="68"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞描述</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="104" width="474"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 存在权限提升漏洞，经过身份认证的远程攻击者可利用此漏洞绕过相关安全特性，获得在系统上下文中运行 PowerShell 的权限。配合其他漏洞可对目标发起进一步利用，实现任意代码执行。</span></p></td></tr><tr style="height:61px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="61" width="68"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响版本</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="61" width="474"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2016 Cumulative Update 23</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2019 Cumulative Update 12</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2019 Cumulative Update 11</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2016 Cumulative Update 22</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2013 Cumulative Update 23</span></p></td></tr><tr style="height:110px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;word-break: break-all;" height="110" width="60"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他受影响组件</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="110" width="474"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">无</span></p></td></tr></tbody></table>  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="3" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;padding: 0px 7px;" height="25" width="470"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>Microsoft Exchange Server</strong><strong>远程代码执行漏洞</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>公开时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="171"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2022-09-30</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="125"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>更新时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2022-10-01</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="171"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2022-41082</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="132"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="151"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2022-26557</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>威胁类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="170"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">代码执行</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="135"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="151"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">数据验证不恰当</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="67"><p><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>厂商</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="169"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="136"><p><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>产品</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="150"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Exchange Server</span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>奇安信</strong><strong>CERT</strong><strong>风险评级</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: rgb(0, 112, 192);">蓝色（一般事件）</span></strong></span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>现时威胁状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="67"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>POC</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="169"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>EXP</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="136"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>在野利用状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="150"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术细节状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="67"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="168"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="136"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已发现</span></strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="149"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr style="height:104px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="104" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞描述</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="104" width="468"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 存在远程代码执行漏洞，经过身份验证的攻击者可利用此漏洞在目标系统上执行任意代码。</span></p></td></tr><tr style="height:61px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="61" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响版本</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="61" width="468"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2016 Cumulative Update 23</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2019 Cumulative Update 12</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2019 Cumulative Update 11</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2016 Cumulative Update 22</span></p><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft Exchange Server 2013 Cumulative Update 23</span></p></td></tr><tr style="height:110px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="110" width="67"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他受影响组件</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="110" width="468"><p style="text-align:justify;line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">无</span></p></td></tr></tbody></table>  
  
威胁评估  
  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="79"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="4" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;padding: 0px 7px;" height="25" width="463"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft   Exchange Server权限提升漏洞</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="79"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="106"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2022-41040</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;word-break: break-all;" height="25" width="190"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="121"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2022-26556</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="79"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>评级</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="106"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="190"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>分数</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="121"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">8.8</span></p></td></tr><tr style="height:25px;"><td rowspan="8" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="79"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS</strong><strong>向量</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="252"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>访问途径（</strong><strong>AV</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>攻击复杂度（</strong><strong>AC</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">网络</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>所需权限（</strong><strong>PR</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>用户交互（</strong><strong>UI</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">不需要</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响范围（</strong><strong>S</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>机密性影响（</strong><strong>C</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未改变</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>完整性影响（</strong><strong>I</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>可用性影响（</strong><strong>A</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="224"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="175"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:127px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="127" width="79"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>危害描述</strong></span></p></td><td colspan="4" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="127" width="463"><p style="line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">经过身份认证的远程攻击者可利用此漏洞绕过相关安全特性，配合其他漏洞可对目标发起进一步利用，实现任意代码执行。</span></p></td></tr><tr height="0"><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);word-break: break-all;" width="79"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="106"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="115"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="53"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="121"><br/></td></tr></tbody></table><table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="76"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="4" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;padding: 0px 7px;" height="25" width="459"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Microsoft   Exchange Server远程代码执行漏洞</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="82"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="108"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2022-41082</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="181"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="126"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2022-26557</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="82"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>评级</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="108"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="181"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>分数</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="126"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">8.8</span></p></td></tr><tr style="height:25px;"><td rowspan="8" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="25" width="82"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS</strong><strong>向量</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="243"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>访问途径（</strong><strong>AV</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>攻击复杂度（</strong><strong>AC</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">网络</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>所需权限（</strong><strong>PR</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>用户交互（</strong><strong>UI</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">不需要</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响范围（</strong><strong>S</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>机密性影响（</strong><strong>C</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未改变</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>完整性影响（</strong><strong>I</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>可用性影响（</strong><strong>A</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="147"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="25" width="179"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:127px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;padding: 0px 7px;" height="127" width="82"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>危害描述</strong></span></p></td><td colspan="4" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);padding: 0px 7px;" height="127" width="459"><p style="line-height: 150%;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">具有执行PowerShell权限的远程攻击者可利用此漏洞在目标系统上执行任意代码。此漏洞可配合CVE-2022-41040 Microsoft Exchange Server权限提升漏洞使用。</span></p></td></tr><tr height="0"><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);word-break: break-all;" width="82"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="108"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="107"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="53"><br/></td><td style="border-width: initial;border-style: none;border-color: rgb(221, 221, 221);" width="126"><br/></td></tr></tbody></table>  
  
处置建议  
  
**微软已于11月发布此漏洞受影响版本的安全补丁，强烈建议受影响的用户尽快安装安全补丁进行防护。建议受影响用户通过以下链接进行手动更新：**  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082  
  
  
**检测方案：**  
  
**一、使用PowerShell命令**  
```
Get-ChildItem -Recurse -Path <Path_IIS_Logs> -Filter "*.log" | Select-String -Pattern 'powershell.*autodiscover\.json.*\@.*200'
```  
  
**二、使用 NCSE0Scanner 检测工具**  
  
GTSC 基于exploit签名开发了扫描 IIS 日志文件的工具，相比 PowerShell，该工具搜索时间更短。以下为工具下载链接：  
  
https://github.com/ncsgroupvn/NCSE0Scanner  
  
**三、使用Microsoft Defender for Endpoint**  
  
用户可启用 Microsoft Defender 防病毒以检测与此次在野利用漏洞相关的 Web Shell 恶意软件。  
  
详情可参考：https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server  
  
**四、入侵指标 (IOC)**  
  
GTSC 安全研究人员还提供了一些可用于识别感染的入侵指标 (IOC)，如下：  
  
**Webshell:**  
  
```
File Name: pxh4HG1v.ashx
Hash (SHA256): c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1
Path: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\pxh4HG1v.ashx
File Name: RedirSuiteServiceProxy.aspx
Hash (SHA256): 65a002fe655dc1751add167cf00adf284c080ab2e97cd386881518d3a31d27f5
Path: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\RedirSuiteServiceProxy.aspx
File Name: RedirSuiteServiceProxy.aspx
Hash (SHA256): b5038f1912e7253c7747d2f0fa5310ee8319288f818392298fd92009926268ca


Path: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\RedirSuiteServiceProxy.aspx
File Name: Xml.ashx
Hash (SHA256): c838e77afe750d713e67ffeb4ec1b82ee9066cbe21f11181fd34429f70831ec1
Path: Xml.ashx
Filename: errorEE.aspx
SHA256: be07bd9310d7a487ca2f49bcdaafb9513c0c8f99921fdf79a05eaba25b52d257
Path: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\errorEE.aspx
```  
  
  
  
**DLL:**  
  
```
File name: Dll.dll
SHA256:
074eb0e75bb2d8f59f1fd571a8c5b76f9c899834893da6f7591b68531f2b5d82
45c8233236a69a081ee390d4faa253177180b2bd45d8ed08369e07429ffbe0a9
9ceca98c2b24ee30d64184d9d2470f6f2509ed914dafb87604123057a14c57c0
29b75f0db3006440651c6342dc3c0672210cfb339141c75e12f6c84d990931c3
c8c907a67955bcdf07dd11d35f2a23498fb5ffe5c6b5d7f36870cf07da47bff2
File name: 180000000.dll (Dump từ tiến trình Svchost.exe)
SHA256: 
76a2f2644cb372f540e179ca2baa110b71de3370bb560aca65dcddbd7da3701e
```  
  
  
  
**IP:**  
  
```
125[.]212[.]220[.]48
5[.]180[.]61[.]17
47[.]242[.]39[.]92
61[.]244[.]94[.]85
86[.]48[.]6[.]69
86[.]48[.]12[.]64
94[.]140[.]8[.]48
94[.]140[.]8[.]113
103[.]9[.]76[.]208
103[.]9[.]76[.]211
104[.]244[.]79[.]6
112[.]118[.]48[.]186
122[.]155[.]174[.]188
125[.]212[.]241[.]134
185[.]220[.]101[.]182
194[.]150[.]167[.]88
212[.]119[.]34[.]11
```  
  
  
**URL:**  
```
hxxp://206[.]188[.]196[.]77:8080/themes.aspx
```  
  
  
**C2:**  
```
137[.]184[.]67[.]33
```  
  
更多细节可参考：https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html。  
  
  
**缓解方案：**  
  
**一、	在 IIS 服务器中添加新的 URL 重写规则**  
  
**1）启用Exchange 紧急缓解服务 (EEMS)**  
  
对于启用了 Exchange 紧急缓解服务 (EEMS) 的客户，Microsoft 发布了适用于 Exchange Server 2016 和 Exchange Server 2019 的 URL 重写缓解措施。该服务会自动启用缓解措施并更新URL重写规则。有关Exchange 紧急缓解服务详情可参考：  
  
https://techcommunity.microsoft.com/t5/exchange-team-blog/new-security-feature-in-september-2021-cumulative-update-for/ba-p/2783155  
  
**2）使用EOMTv2工具**  
  
Microsoft 为 URL 重写缓解步骤创建了脚本工具 EOMTv2，如果没有安装 IIS URL 重写模块，脚本会自动下载并安装该模块。  
  
工具链接：https://aka.ms/EOMTv2  
  
1．使用方法：  
.\EOMTv2.ps1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qyMWibE2rv3yF1fiaGBy0uLoJhvLS28lficm5x3vMUZQPL4PicdJ40ChbKw/640?wx_fmt=png "")  
  
2. 回滚 EOMTv2 缓解措施：  
.\EOMTv2.ps1 -Rollbackmitigation  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qb2c2mKSCa5M89LHwtT1uv6Wh7Ir91iajd0feMpaoiaL1cQ2hRGibP0cDA/640?wx_fmt=png "")  
  
  
**3）手动配置**  
  
1. 打开 IIS 管理器  
  
2. 选择  
Default Web Site  
（默认网站）  
  
3. 在功能视图中选择   
URL 重写  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qTT7QVvghs7FZLQp9rVU8bBkZgpD69WnvHAYwcxLaicngyCKAEgbhTdA/640?wx_fmt=png "")  
  
4. 在右侧的操作窗格中，单击  
添加规则  
，或右键选择添加规则  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qLY939jKXia35axdDoicSFuf8HzgFUkkvLDma60470VhiaeaoxtkWIf0oQ/640?wx_fmt=png "")  
  
5. 选择  
请求阻止  
并单击确定  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qhZylIwib8KDKgtBwxPBRDkExtRzPWFlXbFMGTtB2Kx9AR3Y5lyvd7bQ/640?wx_fmt=png "")  
  
6. 添加字符串”  
(?=.*autodiscover)(?=.*powershell)  
”（不包括引号）  
  
7. **使用**处选择  
正则表达式  
  
8. **阻止方式**处选择  
中止请求  
，然后单击确定  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qqIxC578oQFBcic8xKe1ywUz3c5Rgic5kDlhO5iaNraf1ibWjKBDPQMD6FA/640?wx_fmt=png "")  
  
9. 展开规则并选择模式为”  
(?=.*autodiscover)(?=.*powershell)  
”的规则，然后单击右侧**条件**下的  
编辑  
，或右键选择条件 -> 编辑  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qm1Z5372KDArySCzhWNNXlkiaHFibibqNfA5OibrhaPIowbXk1BsXibwSVnw/640?wx_fmt=png "")  
  
10. 将**条件输入**由 {URL} 更改为 {UrlDecode:{REQUEST_URI}}，点击“确定”  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icQNBdiacyfljINTcicOd2k1qTH4l3AvL5nV3hjA00GU6y6uibTPVuSh0ib2Czwot9t3dGltlWnEKfZNA/640?wx_fmt=png "")  
  
注意：如果需要更改任何规则，最好删除并重新创建  
  
影响：如果按照建议安装 URL Rewrite，对 Exchange 功能没有已知影响  
  
参考：https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/  
  
  
**二、禁止非管理员用户使用远程PowerShell访问**  
  
微软强烈建议Exchange Server用户为组织中的非管理员用户禁用远程 PowerShell访问。  
  
关于如何禁用单用户或多用户远程PoweShell 访问可参考以下链接：  
  
https://learn.microsoft.com/en-us/powershell/exchange/control-remote-powershell-access-to-exchange-servers  
  
  
  
产品解决方案  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全面支持对Microsoft Exchange Server 多个 0Day 漏洞的防护。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7636，建议用户尽快升级检测规则库至2210011240。  
  
  
**奇安信天眼检测方案**  
  
奇安信天眼新一代安全感知系统已经能够有效检测针对该漏洞的攻击，请将规则版本升级到3.0.1001.13572或以上版本。规则ID及规则名称：0x100212F9，Microsoft Exchange Server 远程代码执行漏洞(CVE-2022-41040/41082) 。奇安信天眼流量探针规则升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
参考资料  
  
[1]https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html  
  
[2]https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/  
  
[3]https://www.zerodayinitiative.com/advisories/upcoming/  
  
[4]https://www.bleepingcomputer.com/news/security/new-microsoft-exchange-zero-days-actively-exploited-in-attacks/  
  
[5]https://www.fortinet.com/blog/threat-research/microsoft-exchange-zero-day-vulnerability-updates  
  
[6]https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082  
  
[7]https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040  
  
[8]https://learn.microsoft.com/en-us/powershell/exchange/control-remote-powershell-access-to-exchange-servers  
  
[9]https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082  
  
[10]https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040  
  
  
时间线  
  
2022年9月30日，  
奇安信 CERT发布安全风险通告；  
  
2022年10月1日，奇安信 CERT发布安全风险通告第二次更新；  
  
2022年10月1日，  
奇安信 CERT发布安全风险通告第三次更新；  
  
2022年10月5日，  
奇安信 CERT发布安全风险通告第四次更新；  
  
2022年10月9日，  
奇安信 CERT发布安全风险通告第五次更新；  
  
2022年11月9日，  
奇安信 CERT发布安全风险通告第六次更新；  
  
  
点击**阅读原文**  
到奇安信NOX-安全监测平台查询更多漏洞详情  
  
