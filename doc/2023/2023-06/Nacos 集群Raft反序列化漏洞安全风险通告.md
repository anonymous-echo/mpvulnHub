#  Nacos 集群Raft反序列化漏洞安全风险通告   
 奇安信 CERT   2023-06-06 11:57  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody><tr><td valign="middle" align="center" rowspan="1" colspan="4" style="background-color: rgb(70, 118, 217);border-color: rgb(0, 128, 255);"><p style="line-height: 1.5em;"><span style="color:#ffffff;"><strong><span style="font-size: 13px;">漏洞概述</span></strong></span><br/></p></td></tr><tr><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏</span></strong><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: rgb(0, 128, 255);"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Nacos 集群Raft反序列化漏洞</span></span></p></td></tr><tr><td valign="middle" align="left" rowspan="1" colspan="1" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height:1em;"><span style="font-family:微软雅黑, Microsoft YaHei;"><span style="font-size: 13px;"><strong>漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="border-color: rgb(0, 128, 255);"><p style="line-height:1em;"><span style="color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #FF0000;text-decoration-thickness: initial;display: inline !important;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.578px;text-align: -webkit-left;caret-color: rgb(255, 0, 0);">QVD-2023-13065</span><span style="color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.578px;text-align: -webkit-left;caret-color: rgb(255, 0, 0);"></span></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">公开时间</span></strong></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="163"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-05-25</span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="168"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">影响数量级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">万级</span></p></td></tr><tr><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">漏洞等级</span></strong></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="163"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #ff0000;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高危</span></strong></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="168"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="max-inline-size: 100%;margin: 0px;padding: 0px;box-sizing: border-box !important;overflow-wrap: break-word !important;outline: none 0px !important;cursor: text;color: #000000;font-size: 13px;text-align: -webkit-left;caret-color: #ff0000;text-decoration-thickness: initial;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;">漏洞评分</strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="104"><p style="line-height: 1em;"><span style="text-align: -webkit-left;caret-color: rgb(255, 0, 0);text-decoration-thickness: initial;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;color: rgb(255, 0, 0);display: inline !important;"><strong>8.1</strong></span></p></td></tr><tr><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height: 1em;"><span style="font-size:13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="font-size: 13px;letter-spacing: 0.578px;text-align: -webkit-left;white-space: normal;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">威胁类型</span></strong></span></strong></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="163"><p style="line-height: 1em;"><span style="font-size:13px;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.578px;text-align: -webkit-left;">代码执行</span></span></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="168"><p style="line-height:1em;"><strong><span style="font-size:13px;">利用可能性</span></strong></p></td><td valign="middle" align="left" style="border-color: rgb(0, 128, 255);" width="104"><p style="line-height: 1em;"><span style="color: rgb(255, 169, 0);"><strong><span style="color: rgb(255, 169, 0);font-size: 13px;">中</span></strong></span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="163"><p style="line-height: 1em;"><span style="font-size: 13px;color: rgb(0, 0, 0);"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.578px;text-align: -webkit-left;text-wrap: wrap;">未发现</span></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="168"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="104"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td></tr><tr><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="122"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="163"><p style="line-height: 1em;"><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="168"><p style="line-height: 1em;"><span style="font-size: 13px;"><strong><span style="font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);" width="104"><p style="line-height: 1em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;letter-spacing: 0.578px;text-align: -webkit-left;text-wrap: wrap;font-size: 13px;color: rgb(0, 0, 0);">未发现</span></p></td></tr><tr><td valign="middle" colspan="4" rowspan="1" align="left" style="border-color: rgb(0, 128, 255);"><p style="line-height:1em;"><strong><span style="font-size:13px;">危害描述：</span></strong><span style="font-size:13px;">在Nacos集群处理部分Jraft请求时，攻击者可以无限制使用hessian进行反序列化利用，最终实现代码执行。</span></p></td></tr></tbody></table>  
  
  
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
  
近日，奇安信CERT监测到**Nacos 集群Raft反序列化漏洞(QVD-2023-13065)**，在Nacos集群处理部分Jraft请求时，攻击者可以无限制使用hessian进行反序列化利用，最终实现代码执行。  
**鉴于该漏洞仅影响集群间通信端口 7848（默认配置下），若部署时已进行限制或未暴露则风险可控，建议客户做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
1.4.0<=Nacos<1.4.6  
  
2.0.0<=Nacos<2.2.3  
  
  
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
  
目前官方已发布安全修复更新，受影响用户可以升级到Nacos 1.4.6、Nacos 2.2.3  
  
https://github.com/alibaba/nacos/releases/tag/1.4.6  
  
https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
  
**>**  
**>**  
**>**  
**>**  
  
**缓解措施**  
  
由于该漏洞仅影响7848端口（默认设置下），客户可通过禁止该端口的请求来缓解此漏洞。  
  
  
  
**04**  
  
**参考资料**  
  
[1]https://github.com/alibaba/nacos/releases/tag/1.4.6  
  
[2]https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
  
  
  
**05**  
  
**时间线**  
  
2023年6月6日，奇安信 CERT发布安全风险通告。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibLd70fwmrvibNibTyMBKTcA6ib2FubgKFTUBvky9Hyux53BMicjjOyiciac3m89LeWoNyYGWY9EickIVr2w/640 "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**NOX安全监测平台**  
查看更多漏洞信息。  
  
