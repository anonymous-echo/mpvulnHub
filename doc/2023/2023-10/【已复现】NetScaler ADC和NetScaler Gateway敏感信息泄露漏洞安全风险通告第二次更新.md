#  【已复现】NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞安全风险通告第二次更新   
原创 QAX CERT  奇安信 CERT   2023-10-26 16:23  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffffff;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;">漏洞概述</span></strong><br/></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="114"><p style="line-height: 1em;"><span style="font-size: 13px;letter-spacing: 0px;"><strong><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;letter-spacing: 0px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;" width="114"><p style="line-height:1em;"><span style="font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><span style="color: #000000;letter-spacing: 0.544px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-24045、CVE-2023-4966</span></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="114"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-10-10</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="186"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">十万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="114"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="186"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">9.4</span></strong></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;" width="114"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="font-size:13px;">信息泄露</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="186"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="color: #ff0000;"><strong><span style="font-size: 13px;">高</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="114"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="186"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="color:#ff0000;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="114"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="158"><p style="line-height: 1em;"><strong><span style="font-size: 13px;color: #ff0000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="186"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;" width="99"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;">未授权的远程攻击者利用此漏洞可以目标系统上的获取敏感信息。</span></p></td></tr></tbody></table>  
  
  
**（注：奇安信CERT的漏洞深度分析报告包含此漏洞的POC及技术细节，订阅方式见文末。）**  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Citrix NetScaler Gateway（以前称为Citrix Gateway）和NetScaler ADC（以前称为Citrix ADC）都是Citrix公司的产品。Citrix NetScaler Gateway是一套安全的远程接入解决方案。该方案可为管理员提供应用级和数据级管控功能，以实现用户从任何地点远程访问应用和数据。Citrix Systems NetScaler ADC是一个应用程序交付和安全平台。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到**NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞(CVE-2023-4966)**  
技术细节在互联网上公开。攻击者可以发送恶意请求触发漏洞，读取目标服务器内存中的敏感信息，可以读取到内存中的密钥，借此绕过身份验证  
  
  
**鉴于此漏洞利用简单，产品用量较大，并已存在在野利用，建议客户尽快做好自查及防护。**  
  
  
**本次更新内容：**  
  
**新增产线解决方案；**  
  
**更新受影响资产情况；**  
  
**新增复现截图。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
NetScaler ADC and NetScaler Gateway 14.1 < 14.1-8.50  
  
NetScaler ADC and NetScaler Gateway 13.1 < 13.1-49.15  
  
NetScaler ADC and NetScaler Gateway 13.0 < 13.0-92.19  
  
NetScaler ADC 13.1-FIPS < 13.1-37.164  
  
NetScaler ADC 12.1-FIPS < 12.1-55.300  
  
NetScaler ADC 12.1-NDcPP < 12.1-55.300  
  
**注意：**  
NetScaler ADC 和 NetScaler Gateway 版本 12.1 现已停产 (EOL)，并且容易受到攻击。  
  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**复现情况**  
  
目前，奇安信CERT已成功复现**NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞(CVE-2023-4966)**  
，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibTHHfHQH147ATYa05PQaBOA7CQmbMfeUUPR3V9ZCpZicwaLqRavlIibZHnIib0ucbrmrSAnsugO1RxQ/640 "")  
  
  
  
**04**  
  
**受影响资产情况**  
  
奇安信鹰图资产测绘平台数据显示，NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞(CVE-2023-4966)关联的国内风险资产总数为23357个，关联IP总数为1419个。国内风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibTHHfHQH147ATYa05PQaBObvVibFkbydfic9lwL8SMicKr9ZjfHGvFvUIbIMgXyyC9ViaWhVIn63ym6w/640 "")  
  
  
NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞(CVE-2023-4966)关联的全球风险资产总数为200764个，关联IP总数为20894个。全球风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibTHHfHQH147ATYa05PQaBOxibrFQ6GDvHvZicuvC6NoMvFE9YnMLLLZibuGMibuGrP2EYgBtQdI6ZJzA/640 "")  
  
  
  
  
**05**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方发布新版本修复此漏洞。建议受影响用户可以更新到：  
  
NetScaler ADC and NetScaler Gateway >= 14.1-8.50  
  
NetScaler ADC and NetScaler Gateway 13.1 >= 13.1-49.15  
  
NetScaler ADC and NetScaler Gateway 13.0 >= 13.0-92.19  
  
NetScaler ADC 13.1-FIPS >= 13.1-37.164  
  
NetScaler ADC 12.1-FIPS >= 12.1-55.300  
  
NetScaler ADC 12.1-NDcPP >=  12.1-55.300  
  
**注意：**  
NetScaler ADC 和 NetScaler Gateway 版本 12.1 现已停产 (EOL)。建议客户将其设备升级到安全版本。   
  
  
修复该漏洞之后，已被劫持的会话仍然有效，需要使用如下命令清除已登录的会话：  
```
clar lb persistentSessions <vServer>
```  
  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
**奇安信天眼检测方案**  
奇安信天眼新一代安全感知系统已经能够有效检测针对该漏洞的攻击，请将规则版本升级到3.0.1026.14083或以上版本。规则ID及规则名称：0x100218A9，NetScaler ADC和NetScaler Gateway敏感信息泄露漏洞(CVE-2023-4966)。奇安信天眼流量探针规则升级方法：系统配置->设备升级->规则升级，选择“网络升级”或“本地升级”。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：7971，建议用户尽快升级检测规则库至2310252350以上。  
  
  
**奇安信自动化渗透测试系统检测方案**  
  
奇安信自动化渗透测试系统已经能够有效检测针对该漏洞的攻击，请将插件版本和指纹版本升级到20231024163720以上版本。规则名称：NetScaler ADC 和 NetScaler Gateway CVE-2023-4966 敏感信息泄露漏洞。奇安信自动化渗透测试系统规则升级方法：系统管理->升级管理->插件升级（指纹升级），选择“网络升级”或“本地升级”。  
  
  
**Snort 检测方案**  
  
alert tcp any any -> any 80 (msg:"CVE-2023-4966 detect"; uricontent:"/oauth/idp/.well-known/openid-configuration"; pcre:"/Host:\s[^\n]{20000}/Hmi"; classtype:attempted-recon; sid:1000001; rev:1;)  
  
  
**06**  
  
**参考资料**  
  
[1]https://support.citrix.com/article/CTX579459/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20234966-and-cve20234967  
  
  
  
**07**  
  
**时间线**  
  
2023年10月19日，奇安信 CERT发布安全风险通告；  
  
2023年10月26日，奇安信 CERT发布安全风险通告第二次更新。  
  
  
  
**08**  
  
**漏洞情报服务**  
  
奇安信ALPH  
A威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibTHHfHQH147ATYa05PQaBOv4Nuh5yk5NQ2YKGkibLjShamyTgncs1vIwQFMUr1v41MSsjQY9l2QKA/640 "漏洞订阅上线.png")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibTHHfHQH147ATYa05PQaBOheqTY1R86slK870mNynMa9vDTsF15wNkLU5Jr9DMNf9s851oy5ibADA/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
