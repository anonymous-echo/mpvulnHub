#  【已复现】Nacos 集群Raft反序列化漏洞安全风险通告第二次更新   
原创 QAX CERT  奇安信 CERT   2023-06-08 15:13  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: #4676d9;border-color: #4676d9;"><p style="line-height: 1.5em;"><span style="color:#ffffff;"><strong><span style="font-size: 13px;">漏洞概述</span></strong></span><br/></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #000000;font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Nacos 集群Raft反序列化漏洞</span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><span style="color: #000000;font-size: 13px;letter-spacing: 0.578px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-13065</span></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-05-25</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响对象数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">CVSS 3.1分数</strong></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><strong><span style="text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-size: 13px;color: #ff0000;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">8.1</span></strong></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"></span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">代码执行</span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">利用可能性</span></strong></span></p></td><td valign="middle" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ffc000;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: #ffc000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">中</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="color: #ff0000;font-size: 13px;"><strong><span style="color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已发现</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">已公开</span></strong></span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: #4676d9;"><p style="line-height:1em;"><span style="color: rgba(0, 0, 0, 0.9);font-size: 13px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgba(0, 0, 0, 0.9);font-size: 17px;letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style="color: rgba(0, 0, 0, 0.9);letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;font-size: 13px;display: inline !important;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">危害描述：</span></strong><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;color: rgba(0, 0, 0, 0.9);letter-spacing: 0.544px;text-align: -webkit-left;text-decoration-thickness: initial;font-size: 13px;display: inline !important;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在Nacos集群处理部分Jraft请求时，攻击者可以无限制使用hessian进行反序列化利用，最终实现代码执行。</span></span></p></td></tr></tbody></table>  
  
  
**（注：奇安信CERT的漏洞深度分析报告包含此漏洞的POC及技术细节，订阅方式见文末。）**  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
Nacos是一个易于使用的平台，专为动态服务发现和配置以及服务管理而设计。可以帮助您轻松构建云原生应用程序和微服务平台。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到**Nacos 集群Raft反序列化漏洞(QVD-2023-13065)**  
，在Nacos集群处理部分Jraft请求时，攻击者可以无限制使用hessian进行反序列化利用，最终实现代码执行。  
**鉴于该漏洞仅影响集群间通信端口 7848（默认配置下），若部署时已进行限制或未暴露则风险可控，建议客户做好自查及防护。**  
  
  
**本次更新内容：**  
  
**新增漏洞复现截图；**  
  
**新增产品解决方案；**  
  
**修改PoC公开状态；**  
  
**修改技术细节公开状态。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
1.4.0 <= Nacos < 1.4.6  
  
2.0.0 <= Nacos < 2.2.3  
  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
  
**03**  
  
**复现情况**  
  
目前奇安信CERT已成功复现该漏洞，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49qN70kuhAFTC48Iom6KzttzsUHXBK6sJaVgw0GZbuV53gyAoASPz3LG040JuDxqgkOjAKEK3YYfg/640?wx_fmt=png "")  
  
  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
目前官方已发布安全修复更新，受影响用户可以升级到**Nacos 1.4.6**  
、**Nacos 2.2.3**  
。  
  
https://github.com/alibaba/nacos/releases/tag/1.4.6  
  
https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
由于该漏洞仅影响7848端口（默认设置下），客户可通过禁止该端口的请求来缓解此漏洞。  
  
  
**>**  
**>**  
**>**  
**>**  
  
**产品解决方案**  
  
  
  
  
  
**奇安信网站应用安全云防护系统已更新防护特征库**  
  
奇安信网神网站应用安全云防护系统已全局更新所有云端防护节点的防护规则，支持对Nacos 集群Raft反序列化漏洞(QVD-2023-13065)的防护。  
  
  
**奇安信网神网络数据传感器系统产品检测方案**  
  
奇安信网神网络数据传感器（NDS5000/7000/9000系列）产品，已具备该漏洞的检测能力。规则ID为：52559，建议用户尽快升级检测规则库至2306081330以上。  
  
  
**05**  
  
**参考资料**  
  
[1]https://github.com/alibaba/nacos/releases/tag/1.4.6  
  
[2]https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
  
  
**06**  
  
**时间线**  
  
2023年6月6日，奇安信 CERT发布安全风险通告;  
  
2023年6月8日，奇安信 CERT发布安全风险通告第二次更新。  
  
  
  
**07**  
  
**深度分析报告**  
  
深度分析报告（含PoC和技术细节）已开通订阅，扫描图片  
下方二维码申请：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs48IHHD4rvibpTYGcbUhhnViaZ0vjfJFEKkULw7xIcDsoOFKgU7GcahKZaOQCWaZoCbvzVFDfoWIPYug/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibLd70fwmrvibNibTyMBKTcA6ib2FubgKFTUBvky9Hyux53BMicjjOyiciac3m89LeWoNyYGWY9EickIVr2w/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
