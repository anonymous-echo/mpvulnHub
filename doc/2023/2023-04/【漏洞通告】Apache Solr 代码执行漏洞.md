#  【漏洞通告】Apache Solr 代码执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-04-17 21:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPusJxf0dTMzEyHXJwF72zylY06ClselRzJVDsR48Zwnlasxrj85icPGMw/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
Apache Solr 代码执行漏洞  
  
**组件名称：**  
  
Apache Solr  
  
**影响范围：**  
  
8.10.0 ≤ Apache Solr < 9.2.0  
  
**漏洞类型：**  
  
远程代码执行  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：  
  
（1）solr以cloud模式启动  
  
（2）solr服务器可以访问互联网  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可远程代码执行。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPuDHSwIez50ZI4ThIk3KBVFjhvumdzqk4suxSjGRXzLDvrgibicI25l2xw/640?wx_fmt=gif "")  
  
**组件介绍**  
  
Apache Solr 是一个开源的搜索服务器。Solr 使用 Java 语言开发，主要基于 HTTP 和 Apache Lucene 实现。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPuDHSwIez50ZI4ThIk3KBVFjhvumdzqk4suxSjGRXzLDvrgibicI25l2xw/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年4月17日，深信服安全团队监测到一则Apache Solr组件存在代码执行漏洞的信息，漏洞编号：CNVD-2023-27598，漏洞威胁等级：高危。  
  
该漏洞是由于Apache Solr的配置可被未授权修改，**攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行远程代码执行攻击，最终获取服务器权限。**  
  
  
**影响范围**  
  
目前受影响的Apache Solr版本：  
  
8.10.0 ≤ Apache Solr < 9.2.0  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPuDHSwIez50ZI4ThIk3KBVFjhvumdzqk4suxSjGRXzLDvrgibicI25l2xw/640?wx_fmt=gif "")  
  
**如何检测组件版本**  
  
  
访问Solr后台页面即可获取版本号。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPu59NkW3iaiaib6vyH9ibKneyictc8AYfhMmHDsDFZZBZIt2UQgYuFjnxpPZg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPuDHSwIez50ZI4ThIk3KBVFjhvumdzqk4suxSjGRXzLDvrgibicI25l2xw/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://solr.apache.org/downloads.html  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPuDHSwIez50ZI4ThIk3KBVFjhvumdzqk4suxSjGRXzLDvrgibicI25l2xw/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对Apache Solr 的主动检测，可批量检出业务场景中该事件的受影响资产情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞安全监测**  
  
支持对Apache Solr代码执行漏洞的监测，可依据流量收集实时监控业务场景中的受影响资产情况，快速检查受影响范围，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2023年4月20日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年4月20日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计预计2023年4月20日发布检测方案。  
  
  
**3.漏洞安全防护**  
  
支持对Apache Solr代码执行漏洞的防御，可阻断攻击者针对该事件的入侵行为，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2023年4月20日发布防护方案。  
  
**【深信服终端安全管理系统EDR】**预计2023年4月20日发布防护方案。  
  
**【深信服Web应用防火墙WAF】**预计20  
23年4月20日  
发布防护方案。  
  
**【深信服安全托管服务MSS】**预计2023年4月20日发布防护方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年4月20日发布防护方案。  
  
  
**参考链接**  
  
https://blog.noah.360.net/apache-Solr-rce/  
  
  
**时间轴**  
  
  
  
**2023/4/17**  
  
深信服监测到Apache Solr代码执行漏洞信息。  
  
  
**2023/4/17**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPu0cpUCFbOF9yI53KGIT9fMvd4nuhUWq6l99IEAZmpS5o1ISSV6e41lQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yjJLGgXmq4bwXPTsWgOFPuqcX7xBdsxYTqVHSzozDOgfl8LvBX0EiajvGU7YrvScKq7bISzoKgW7A/640?wx_fmt=jpeg "")  
  
  
