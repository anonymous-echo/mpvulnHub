#  JumpServer 多个高危漏洞安全风险通告   
QAX CERT  奇安信 CERT   2023-09-27 17:59  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="87"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">JumpServer 多个高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="87"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-42820、CVE-2023-43650、CVE-2023-42819、CVE-2023-43651</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="87"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-09-27</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="193"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="110"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="87"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="193"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">利用可能性</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="110"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></strong></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="87"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="color: #ff0000;font-size: 13px;"><strong><span style="color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="193"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="110"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="87"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="167"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="193"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="110"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用条件：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">CVE-2023-42820、CVE-2023-43650需未开启MFA；CVE-2023-42819、CVE-2023-43651需要低权限。</span></p></td></tr></tbody></table>  
  
  
**（注：奇安信CERT的漏洞深度分析报告包含此漏洞的POC及技术细节，订阅方式见文末。）**  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
JumpServer   
是广受欢迎的开源堡垒机，是符合  
4A   
规范的专业运维安全审计系统，可以帮助企业以更安全的方式管控和登录各种类型的资产。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到JumpServer 密码重置漏洞(CVE-2023-42820)、JumpServer 任意密码重置漏洞(CVE-2023-43650)、Jumpserver 目录遍历漏洞(CVE-2023-42819)，JumpServer koko 远程命令执行漏洞(CVE-2023-43651)。成功利用这些漏洞可以实现认证前命令执行。  
  
<table><tbody><tr><td valign="top" style="border-color: #4676d9;background-color: #4676d9;"><p style="line-height: 1.5em;"><span style="font-size: 13px;"><strong><span style="letter-spacing: 0px;color: #ffffff;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="top" style="border-color: #4676d9;background-color: #4676d9;"><p style="line-height: 1.5em;"><span style="font-size: 13px;"><strong><span style="letter-spacing: 0px;color: #ffffff;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞描述</span></strong></span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size: 13px;">JumpServer 密码重置漏洞(CVE-2023-42820)</span></p></td><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">该漏洞是由于第三方库向 API 公开了随机数种子，验证码可被计算推演。当MFA未开启时，未经身份验证的攻击者可以重放随机生成的验证码，从而导致任意密码重置。</span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">Jumpserver 目录遍历漏洞(CVE-2023-42819)</span></p></td><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">经过身份验证的远程攻击者，可以利用该漏洞访问和修改系统上任何文件的内容，最终可导致命令执行。</span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">JumpServer 任意密码重置漏洞(CVE-2023-43650)</span></p></td><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">该漏洞是由于JumpServer 没有对重置用户密码的验证码的验证频率进行速率限制，在没有开启MFA时，可以通过暴力破解重置任意用户密码。</span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">JumpServer koko 远程命令执行漏洞(CVE-2023-43651)</span></p></td><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height:2em;"><span style="font-size:13px;">经过身份验证的用户可以利用 MongoDB 会话中的漏洞执行任意命令，从而导致远程代码执行。该漏洞可能会被进一步利用来获得主机系统的 root 权限。</span></p></td></tr></tbody></table>  
  
**鉴于这些漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
**JumpServer 密码重置漏洞(CVE-2023-42820)：**  
  
2.24 <= jumpserverv 2.x <= 2.28.20  
  
jumpserverv 3.x <= 3.6.4  
  
  
**JumpServer 任意密码重置漏洞(CVE-2023-43650)：**  
  
2.24 <= jumpserverv 2.x <= 2.28.20  
  
jumpserverv 3.x <= 3.6.4  
  
  
**Jumpserver 目录遍历漏洞(CVE-2023-42819)：**  
  
3.0.0 <= jumpserver <= 3.6.4  
  
  
**JumpServer koko 远程命令执行漏洞(CVE-2023-43651)：**  
  
2.24 <= jumpserverv 2.x <= 2.28.20  
  
jumpserverv 3.x <= 3.6.4  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**复现情况**  
  
目前，奇安信CERT已成功复现**Jumpserver 目录遍历漏洞(CVE-2023-42819)**  
，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icAQr2z6XWFlv3suN4vE2unybQGJyuyGJUlEV4xKqrnTE77ica6x59hJD32nJtHJHlrfnx1oJlaqlQ/640 "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已发布更新，受影响用户可以更新到安全版本：  
  
jumpserverv 2.x >= 2.28.20  
  
jumpserverv 3.x >= 3.7.1  
  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
**奇安信开源卫士已支持**  
  
奇安信开源卫士20230927. 398版本已支持对Jumpserver 目录遍历漏洞(CVE-2023-42819)的检测。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7953 ，建议用户尽快升级检测规则库至2309271200以上；  
  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全局更新所有云端防护节点的防护规则，支持对Jumpserver 目录遍历漏洞(CVE-2023-42819)的防护。  
  
  
**奇安信天眼产品解决方案**  
  
奇安信天眼新一代威胁感知系统在第一时间加入了该漏洞的检测规则，请将规则包升级到3.0.0926.14065及以上版本。  
  
规则名称：Jumpserver 目录遍历漏洞(CVE-2023-42819)  
  
规则ID：0x1002186F  
  
奇安信天眼流量探针（传感器）升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**05**  
  
**参考资料**  
  
[1]https://github.com/jumpserver/jumpserver/releases   
  
[2]https://github.com/jumpserver/jumpserver/security/advisories/GHSA-7prv-g565-82qp  
  
[3]https://github.com/jumpserver/jumpserver/security/advisories/GHSA-mwx4-8fwc-2xvw  
  
[4]https://github.com/jumpserver/jumpserver/security/advisories/GHSA-ghg2-2whp-6m33  
  
[5]https://github.com/jumpserver/jumpserver/security/advisories/GHSA-4r5x-x283-wm96  
  
[6]https://docs.jumpserver.org/zh/master/admin-guide/authentication/mfa/  
  
  
  
**06**  
  
**时间线**  
  
2023年9月27日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**漏洞情报服务**  
  
奇安信ALPH  
A威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibUhhAQkqA4UaEJvRBB1DbaAOmXXibCXnxurOa2n3vQkMfic8TlJ42pFzCSDvIPRaWbWtZva7YD7iatw/640 "漏洞订阅上线.png")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibUhhAQkqA4UaEJvRBB1DbaHck6KxjUw68yJPHnfFdwEibicTWbrhJAj2lH7QFcophT3UiceAuZEOL2A/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
