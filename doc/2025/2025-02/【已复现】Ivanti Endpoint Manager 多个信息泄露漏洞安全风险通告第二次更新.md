#  【已复现】Ivanti Endpoint Manager 多个信息泄露漏洞安全风险通告第二次更新   
 奇安信 CERT   2025-02-20 03:40  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="center" rowspan="1" colspan="4" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);background-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 255, 255);letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;">漏洞概述</span></strong><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">Ivanti Endpoint Manager 信息泄露漏洞</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" rowspan="1" colspan="1" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">CVE-2024-10811、CVE-2024-13161、</span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;caret-color: rgb(255, 0, 0);letter-spacing: 0.544px;text-align: justify;visibility: visible;">CVE-2024-13160、CVE-2024-13159</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">公开时间</span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">2025-01-14</span></p></td><td valign="middle" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">影响量级</span></strong></span></p></td><td valign="middle" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">万级</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;caret-color: rgb(255, 0, 0);font-size: 13px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">9.8</span></strong></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">威胁类型</span></strong><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"></span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;letter-spacing: normal;caret-color: rgb(255, 0, 0);visibility: visible;">信息泄露</span></span></p></td><td valign="middle" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">利用可能性</span></strong></p></td><td valign="middle" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">高</span></strong></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0.544px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 13px;text-align: -webkit-left;caret-color: rgb(255, 0, 0);color: rgb(0, 0, 0);letter-spacing: 0.544px;background-color: rgb(255, 255, 255);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">已公开</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">未发现</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 13px;text-align: -webkit-left;caret-color: rgb(255, 0, 0);color: rgb(0, 0, 0);letter-spacing: 0.544px;background-color: rgb(255, 255, 255);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">已公开</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0.544px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 13px;text-align: -webkit-left;caret-color: rgb(255, 0, 0);color: rgb(0, 0, 0);letter-spacing: 0.544px;background-color: rgb(255, 255, 255);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">已公开</span></strong></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="4" rowspan="1" align="left" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">危害描述：</span></strong><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0.544px;visibility: visible;">允许远程未经身份验证的攻击者泄露敏感信息。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Ivanti Endpoint Manager（EPM）是由Ivanti公司开发的一款综合性端点管理解决方案，它帮助企业有效管理和保护网络中的端点设备，包括桌面、笔记本电脑、服务器、移动设备和虚拟环境等。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到**Ivanti Endpoint Manager 信息泄露漏洞(CVE-2024-10811、CVE-2024-13161、CVE-2024-13160、CVE-2024-13159)**在互联网上公开。在 Ivanti EPM 的代理门户中，存在多个绝对路径遍历漏洞。这些漏洞允许远程未经身份验证的攻击者泄露敏感信息。**目前该漏洞技术细节与POC已在互联网上公开，**  
**鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。**  
****  
  
****  
**本次更新内容：**  
  
**更新漏洞状态；**  
  
**新增产线解决方案；**  
  
**新增复现截图。**  
  
****  
****  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Ivanti Endpoint Manager <= 2024 November security update  
  
Ivanti Endpoint Manager <= 2022 SU6 November security update  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
**03**  
  
**复现情况**  
  
目前，奇安信威胁情报中心安全研究员已成功复现**Ivanti Endpoint Manager 信息泄露漏洞(CVE-2024-13159)******，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EkibxOB3fs48jrRPibWibQFtuicKX38zGcXjicFqECibMQfDjraVDMmAD4kVpxGaMtRt2qYQsJWTWlyVibZfmFHsYQDHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
Ivanti Endpoint Manager EPM 2024 January-2025 Security Update, EPM 2022  
  
Ivanti Endpoint Manager SU6 January-2025 Security Update  
  
官方补丁下载地址：  
  
https://download.ivanti.com/downloads/Patch/component/EPM2024/Security/Flat/EPM_2024_Flat_Jan_2025_Patch.zip  
  
https://download.ivanti.com/downloads/Patch/component/EPM2022/Security/SU6/EPM_2022_SU6_Jan_2025_Patch.zip  
  
**修复缓解措施：**  
  
在官方补丁发布之前，用户可以采取以下缓解措施：  
  
1.限制对Ivanti EPM服务器的网络访问，仅允许信任的IP地址或网络段进行访问。  
  
2.对输入的文件路径进行严格的验证和过滤，确保只允许访问合法的文件路径。  
  
3.定期对服务器进行安全检查和漏洞扫描，及时发现并修复潜在的安全问题。  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全局更新所有云端防护节点的防护规则，支持对Ivanti Endpoint Manager 信息泄露漏洞(CVE-2024-13159)的防护。  
  
  
**奇安信天眼检测方案**  
  
奇安信天眼新一代威胁感知系统在第一时间加入了该漏洞的检测规则，请将规则包升级到3.0.0220.14652及以上版本。  
  
规则名称：Ivanti Endpoint Manager 信息泄露漏洞(CVE-2024-13159)  
  
规则ID：0x100220E9  
  
奇安信天眼流量探针（传感器）升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**奇安信自动化渗透测试系统检测方案**  
  
奇安信自动化渗透测试系统已经能够有效检测针对该漏洞的攻击，请将插件版本和指纹版本升级到202502212600以上版本。规则名称：Ivanti Endpoint Manager CVE-2024-13159 信息泄露漏洞。奇安信自动化渗透测试系统规则升级方法：系统管理->升级管理->插件升级（指纹升级），选择“网络升级”或“本地升级”。  
  
  
  
  
**05**  
  
**参考资料**  
  
[1]https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6  
  
[2]https://www.horizon3.ai/attack-research/attack-blogs/ivanti-endpoint-manager-multiple-credential-coercion-vulnerabilities/  
  
  
  
**06**  
  
**时间线**  
  
2025年01月15日，奇安信 CERT发布安全风险通告。  
  
2025年02月20日，奇安信 CERT发布安全风险通告第二次更新。  
  
  
  
**07**  
  
**漏洞情报服务**  
  
奇安信ALPH  
A威胁分析平台已支持漏洞情报订阅服务：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BY9IJ0MPzeiashvK2XLpdl3XtTtCD91h0jS26fqvuWpEMXgmXa85qLkoA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "漏洞订阅上线.png")  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BYBVaibvBq1vXprZIc191LXKibdiaApA16q3UgmibQDv4yW09qT88J3jRUfA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
