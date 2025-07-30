#  Apache Dubbo多个反序列化漏洞安全风险通告   
 奇安信 CERT   2023-12-18 17:04  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="color: #ffffff;font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="115"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;caret-color: red;letter-spacing: 0px;">Apache Dubbo多个反序列化漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="115"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-29234、CVE-2023-46279</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="115"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="192"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-12-15</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="155"><p style="line-height:1em;"><strong><span style="font-size:13px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="95"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">十万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="115"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="192"><p style="line-height: 1em;"><span style="letter-spacing:0px;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;letter-spacing: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="155"><p style="line-height: 1em;"><strong><span style="font-size: 13px;">CVSS 评分</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="95"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;color: #000000;">7.7、8.1</span></p></td></tr><tr><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="115"><p style="line-height:1em;"><span style="font-size:13px;"><strong>威胁类型</strong></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="192"><p style="line-height:1em;"><span style="font-size:13px;">信息泄露、代码执行</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="155"><p style="line-height:1em;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 17px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;font-size: 13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" style="border-color: #4676d9;" width="95"><p style="line-height:1em;"><strong><span style="max-inline-size: 100%;margin: 0px;padding: 0px;cursor: text;font-size: 13px;color: #f79646;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;">中</span></strong></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="115"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="192"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="155"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="95"><p style="line-height: 1em;"><span style="color: #000000;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="115"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="192"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="155"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="95"><p style="line-height: 1em;"><span style="font-size: 13px;color: #000000;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">攻击者可能利用此漏洞获取敏感信息或执行恶意代码。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Apache Dubbo 是一款高性能、轻量级的开源 Java 服务框架。Apache Dubbo提供了六大核心能力：面向接口代理的高性能RPC调用，智能容错和负载均衡，服务自动注册和发现，高度可扩展能力，运行期流量调度，可视化的服务治理与运维。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到**Apache Dubbo发布新版本修复了Apache Dubbo 反序列化漏洞(CVE-2023-46279)与Apache Dubbo 反序列化漏洞(CVE-2023-29234)**  
，攻击者通过向系统发送恶意数据包利用这些漏洞，成功后可以读取敏感信息或执行恶意代码。  
  
<table><tbody><tr><td valign="middle" align="center" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 2em;"><span style="color: #ffffff;"><strong><span style="font-size: 13px;letter-spacing: 0px;color: #ffffff;">漏洞名称</span></strong></span></p></td><td valign="middle" align="center" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 2em;"><span style="color: #ffffff;"><strong><span style="font-size: 13px;letter-spacing: 0px;color: #ffffff;">漏洞描述</span></strong></span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height: 2em;"><span style="font-size: 13px;letter-spacing: 0px;">Apache Dubbo发布新版本修复了Apache Dubbo 反序列化漏洞(CVE-2023-46279)</span></p></td><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height: 2em;"><span style="font-size: 13px;letter-spacing: 0px;">Apache Dubbo中存在反序列化漏洞，攻击者利用该漏洞可以绕过拒绝反序列化列表检查触发反序列化错误，最终泄露敏感信息或执行恶意代码。</span></p></td></tr><tr><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height: 2em;"><span style="font-size: 13px;letter-spacing: 0px;">Apache Dubbo 反序列化漏洞(CVE-2023-29234)</span></p></td><td valign="middle" style="border-color: #4676d9;" align="left"><p style="line-height: 2em;">Apache Dubbo中存在反序列化漏洞，攻击者可以通过向系统发生恶意数据包绕过反序列化检查，触发反序列化漏洞，泄露敏感信息或执行恶意代码。</p></td></tr></tbody></table>  
  
**鉴于此产品用量较大，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
Apache Dubbo 反序列化漏洞(CVE-2023-46279)：  
  
Apache Dubbo == 3.1.5  
  
  
Apache Dubbo 反序列化漏洞(CVE-2023-29234)：  
  
Apache Dubbo 3.2.x <= 3.2.4  
  
Apache Dubbo 3.1.x <= 3.1.10  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已有可更新版本，建议受影响用户升级至最新版本。  
  
https://github.com/apache/dubbo/releases  
  
  
  
**04**  
  
**参考资料**  
  
[1]https://lists.apache.org/thread/zw53nxrkrfswmk9n3sfwxmcj7x030nmo  
  
[2]https://lists.apache.org/thread/wb2df2whkdnbgp54nnqn0m94rllx8f77  
  
[3]https://github.com/apache/dubbo/releases  
  
  
  
**05**  
  
**时间线**  
  
2023年12月18日，奇安信 CERT发布安全风险通告。  
  
  
  
**06**  
  
**漏洞情报服务**  
  
奇安信ALPHA威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icvtfpU85HMgqgQaWBcvFdZZmoic7vD8p42wrTeAdC0cg22eL2YQKBnrWG5Qo5PlLNMrXb6sSK7NnQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icvtfpU85HMgqgQaWBcvFdZsmn5udmic0X8LdayHFR9R6efswBebPwhibMtR781jAjo2rDWN1LA6yzg/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到  
**ALHA威胁分析平台**  
订阅更多漏洞信息。  
  
