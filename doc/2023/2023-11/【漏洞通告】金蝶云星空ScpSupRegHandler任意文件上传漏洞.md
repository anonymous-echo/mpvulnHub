#  【漏洞通告】金蝶云星空ScpSupRegHandler任意文件上传漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-11-20 19:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbuNWe6lsbKvEIicPibiagH5RiaGDaUChyl8rFWnOlkAPoefHJmItmwxzMkA/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
金蝶云星空ScpSupRegHandler任意文件上传漏洞  
  
**组件名称：**  
  
金蝶云星空  
  
**影响范围：**  
  
金蝶云星空企业版私有云、企业版私有云（订阅）、标准版私有云（订阅）三个产品  
  
V6.2(含17年12月补丁) 至 V8.1(含23年9月补丁)  
  
**漏洞类型：**  
  
任意文件上传  
  
**利用条件：**  
  
1、用户认证：不需要用户认证  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，可上传任意文件。  
  
<综合评定威胁等级>：高危，可上传任意文件。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbHvlic9ichnRxwyDd4Fs1R7uCSHTXNLemMntCBvS5G9kgnIXrUFx2511w/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
金蝶云星空-管理中心是一款基于云计算技术的企业管理软件，旨在为企业提供全面的管理解决方案。该软件集成了财务、人力资源、采购、销售等多个模块，支持多语言、多币种、多账套等功能，能够满足不同企业的管理需求。同时，金蝶云星空-管理中心还具备高效的数据分析和报表功能，帮助企业实现精细化管理和决策。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbHvlic9ichnRxwyDd4Fs1R7uCSHTXNLemMntCBvS5G9kgnIXrUFx2511w/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
2023年11月20日，深信服安全团队监测到一则金蝶云星空组件存在任意文件上传漏洞的信息，漏洞威胁等级：高危。  
  
  
金蝶云星空的ScpSupRegHandler接口存在任意文件上传漏洞，远程**攻击者可以利用此漏洞上传任意文件。**  
  
  
**影响范围**  
  
金蝶云星空企业版私有云、企业版私有云（订阅）和标准版私有云（订阅）三个产品 V6.2(含17年12月补丁) 至 V8.1(含23年9月补丁)  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbHvlic9ichnRxwyDd4Fs1R7uCSHTXNLemMntCBvS5G9kgnIXrUFx2511w/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
官方已发布新版本修复漏洞，建议尽快访问官网或联系官方售后支持获取版本升级安装包或补丁，链接如下：https://vip.kingdee.com/article/505394681531036160?productLineId=1&%3BisKnowledge=2&isKnowledge=2  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbHvlic9ichnRxwyDd4Fs1R7uCSHTXNLemMntCBvS5G9kgnIXrUFx2511w/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对金蝶云星空ScpSupRegHandler的主动检测，可批量检出业务场景中该事件的受影响资产情况，相关产品如下：  
  
【深信服云镜YJ】已发布资产检测方案。  
  
  
**2.漏洞主动扫描**  
  
支持对金蝶云星空ScpSupRegHandler任意文件上传漏洞的主动扫描，可批量快速检出业务场景中是否存在漏洞风险，相关产品如下：  
  
**【深信服云镜YJ】**已发布扫描方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年11月20日发布扫描方案。  
  
**【深信服安全托管服务MSS】**预计2023年11月20日发布扫描方案。  
  
（需要具备TSS组件能力）。  
  
**【深信服安全检测与响应平台XDR】**已发布扫描方案，（需要具备云镜组件能力）。  
  
  
**3.漏洞安全监测**  
  
支持对金蝶云星空ScpSupRegHandler任意文件上传漏洞的监测，可依据流量收集实时监控业务场景中的受影响资产情况，快速检查受影响范围，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**已发布检测方案。  
  
**【深信服安全托管服务MSS】**已发布检测方案，（需要具备SIP组件能力）。  
  
**【深信服安全检测与响应平台XDR】**已发布检测方案。  
  
  
**4.漏洞安全防护**  
  
支持对金蝶云星空ScpSupRegHandler任意文件上传漏洞的防御，可阻断攻击者针对该事件的入侵行为，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**已发布防护方案。  
  
**【深信服Web应用防火墙WAF】**已发布防护方案。  
  
**【深信服终端安全管理系统EDR】**已发布防护方案。  
  
**【深信服安全托管服务MSS】**已发布防护方案，（需要具备AF组件能力）。  
  
**【深信服安全检测与响应平台XDR】**已发布防护方案，（需要具备AF组件能力）。  
  
  
**参考链接**  
  
  
https://vip.kingdee.com/article/505394681531036160?productLineId=1&%3BisKnowledge=2&isKnowledge=2  
  
  
**时间轴**  
  
  
  
**2023/11/20**  
  
 官方发布升级补丁。  
  
  
**2023/11/20**  
  
深瞳漏洞实验室发布漏洞通告。  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbNqBriaCIgMJP7pCGVXQFycRggNgBsHoSB2ycpEVSZXqlF1t2EVHEk0A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5z4REWgiabuvPOmYohb8mLHbLIqvOd1tEnSKsTgQZOIxHcTLaXrTr75Na6zFp7QHbu1x9jgBEibszdA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
