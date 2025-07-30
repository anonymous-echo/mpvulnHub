#  【已复现】Apache NiFi 多个高危漏洞安全风险通告   
原创 QAX CERT  奇安信 CERT   2023-06-14 11:12  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Apache NiFi 多个高危漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-13638、<span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-34212</span></span></p><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-13637、CVE-2023-34468</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-06-12</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">8.3</span></strong></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size:13px;">代码执行</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffc000;"><strong><span style="font-size: 13px;">中</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用条件：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">需要经过身份验证。</span></p></td></tr></tbody></table>  
  
  
**（注：奇安信CERT的漏洞深度分析报告包含Apache NiFi反序列化漏洞(CVE-2023-34212)的POC及技术细节，订阅方式见文末。）**  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Apache NiFi 是一个易于使用、功能强大而且可靠的数据处理和分发系统。Apache NiFi 是为数据流设计。它支持高度可配置的指示图的数据路由、转换和系统中介逻辑。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT安全研究员发现**Apache NiFi反序列化漏洞(CVE-2023-34212)**  
，经过身份认证的远程攻击者利用该漏洞可以执行代码或造成崩溃。Apache NiFi新版本修复的还有另一高危漏洞**Apache NiFi 代码执行漏洞(CVE-2023-34468)**  
，经过身份认证的远程攻击者利用此漏洞可以执行代码。  
**鉴于这些漏洞影响较大，建议客户尽快做好自查及防护。**  
  
<table><tbody><tr><td valign="middle" style="border-color: rgb(70, 118, 217);background-color: rgb(70, 118, 217);word-break: break-all;" align="center" width="152"><p style="line-height:2em;"><span style="font-size: 12px;"><strong><span style="font-size: 12px;letter-spacing: 0px;color: rgb(255, 255, 255);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" style="border-color: #4676d9;background-color: #4676d9;" align="center" width="446"><p style="line-height:2em;"><span style="font-size: 12px;"><strong><span style="font-size: 12px;letter-spacing: 0px;color: rgb(255, 255, 255);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞描述</span></strong></span></p></td></tr><tr style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px 10px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;"><td valign="middle" style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px 10px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;" align="left" width="125"><section style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;"><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">Apache NiFi 反序列化漏洞(CVE-2023-34212)</span></section></td><td valign="middle" style="line-height: 1em;border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px 10px;" align="left" width="426"><p style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px;line-height: 1.6em;"><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">Apache NiFi存在反序列化漏洞，JndiJmsConnectionFactoryProvider控制器服务以及ConsumeJMS和PublishJMS处理器允许经过身份验证和授权的用户配置URL和库属性，从而使得来自远程的不受信任的数据可以进行反序列化，经过身份认证的远程攻击者利用该漏洞可以执行代码或造成崩溃。</span></p></td></tr><tr style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px 10px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;"><td valign="middle" style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px 10px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;" align="left" width="152"><section style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;"><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">Apache NiFi 代码执行漏洞(CVE-2023-34468)</span></section></td><td valign="middle" style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px 10px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;" align="left" width="446"><section style="border-color: rgb(70, 118, 217);box-sizing: border-box;margin: 0px;line-height: 1.6em;text-align: justify;color: rgb(51, 51, 51);font-size: 14px;text-shadow: none;letter-spacing: 1.5px;"><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">Apache NiFi存在代码执行漏洞，DBCPConnectionPool和HikariCPConnectionPool控制器服务允许经过身份验证和授权的用户配置带有H2驱动程序的数据库URL，从而实现代码执行。</span></section></td></tr></tbody></table>  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
**Apache NiFi 反序列化漏洞(CVE-2023-34212)：**  
  
1.8.0 <= Apache NiFi <= 1.21.0  
  
  
**Apache NiFi 代码执行漏洞(CVE-2023-34468)：**  
  
0.0.2 <= Apache NiFi <= 1.21.0  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**复现情况**  
  
目前，奇安信CERT已成功复现**Apache NiFi反序列化漏洞(CVE-2023-34212)**  
，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48P0BxEQBtzkT0qVjkFnXhIU9ZLccM5J08YfVhFiar8I7fZWibRqEgXeHGpNzv1iceg2DeeL4KGe3K2A/640 "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
升级版本至**1.22.0及以上：**  
  
https://nifi.apache.org/download.html  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
**Apache NiFi 反序列化漏洞(CVE-2023-34212)：**  
  
在默认配置中为JNDI URL禁用 LDAP、RMI  
  
  
**Apache NiFi 代码执行漏洞(CVE-2023-34468)：**  
  
在默认配置中禁用 H2 JDBC URL  
  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
**奇安信开源卫士已支持**  
  
奇安信开源卫士202300613. 294版本已支持对Apache NiFi反序列化漏洞(CVE-2023-34212)的检测。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7781，建议用户尽快升级检测规则库至2306131700以上。  
  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全局更新所有云端防护节点的防护规则，支持对Apache NiFi反序列化漏洞(CVE-2023-34212)的防护。  
  
  
**奇安信天眼产品解决方案**  
  
奇安信天眼新一代威胁感知系统在第一时间加入了该漏洞的检测规则，请将规则包升级到3.0.0613.13909上版本。规则名称：Apache NiFi反序列化漏洞(CVE-2023-34212)，规则ID：0x1002168C。奇安信天眼流量探针（传感器）升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**Snort 检测方案**  
  
Snort是一个开源的入侵检测系统，使用规则来检测网络流量中的恶意行为。用户可参考以下Snort检测规则，进行Apache NiFi反序列化漏洞(CVE-2023-34212)的检测：  
  
alert tcp any any -> any any (msg:"Possible vulnerability"; content:"PUT"; nocase; http_method; content:"/nifi-api/controller-services/"; http_uri; content:"java.naming.provider.url":"; http_client_body; pcre:"/java\.naming\.provider\.url":"(ldap|rmi)/Ui"; sid:100001;)  
  
  
**05**  
  
**参考资料**  
  
[1]https://nifi.apache.org/security.html  
  
[2]https://lists.apache.org/thread/w5rm46fxmvxy216tglf0dv83wo6gnzr5  
  
[3]https://lists.apache.org/thread/7b82l4f5blmpkfcynf3y6z4x1vqo59h8  
  
  
  
**06**  
  
**时间线**  
  
2023年6月13日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**深度分析报告**  
  
深度分析报告（含PoC和技术细节）已开通订阅，扫描图片  
下方二维码申请：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibGRjNVNSdSvJ5L9nlicWz14DRBD2bHbQMppe497uYgKdgbCWddmjzUpUtXVkibjDA8iaCTMsyncAulg/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibGRjNVNSdSvJ5L9nlicWz14CvpjLaxfqcTvVwicRe3ZQxeGXRHTsvibib24eaOR6xH49sD6kFnKIyXiaQ/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
