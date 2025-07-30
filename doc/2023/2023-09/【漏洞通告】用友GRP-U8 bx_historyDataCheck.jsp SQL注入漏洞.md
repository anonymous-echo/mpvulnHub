#  【漏洞通告】用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-09-22 16:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaHukgUnn52zJvjP4WQ9Gl0op1VIlPUJgnUxRRfxnfMUpic7MLXZvB4fQ/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞  
  
**组件名称：**  
  
用友GRP-U8  
  
**影响范围：**  
  
用友GRP-U8 U8Manager版本B、C、G系列  
  
**漏洞类型：**  
  
SQL注入  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权。  
  
<综合评定威胁等级>：高危，能造成信息泄露。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**组件介绍**  
  
用友GRP-U8是一款企业管理软件，专为大型企业提供财务、采购、库存、生产等业务管理解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年9月22日，深信服安全团队监测到一则用友GRP-U8组件存在SQL注入漏洞的信息，漏洞威胁等级：高危。  
  
该漏洞是由于用友GRP-U8未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。**攻击者可利用该漏洞在未授权的情况下，发送构造好的恶意数据，导致感敏信息泄露。**  
  
  
**影响范围**  
  
目前受影响的用友GRP-U8版本：  
  
用友GRP-U8 U8Manager版本B、C、G系列  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://security.yonyou.com/#/noticeInfo?id=379  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对用友GRP-U8 组件的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞的主动检测，可**批量快速检出**业务场景中是否存在**漏洞风险**，相关产品如下：  
  
**【深信服云镜YJ】**预计2023年9月24日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年9月25日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月25日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月25日发布检测方案。  
  
  
**3.漏洞安全监测**  
  
支持对用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞的监测，可依据流量收集**实时监控**业务场景中的**受影响资产情况，快速检查受影响范围**，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2023年9月25日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月25日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月25日发布检测方案。  
  
  
**4.漏洞安全防护**  
  
支持对用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞的防御，**可阻断攻击者针对该事件的入侵行为**，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2023年9月25日发布检测方案。  
  
**【深信服Web应用防火墙WAF】**预计2023年9月25日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月25日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月25日发布检测方案。  
  
  
**参考链接**  
  
  
https://security.yonyou.com/#/patchInfo?foreignKey=7bd5b43e2c984a618b2b1d3f288110ae  
  
  
**时间轴**  
  
  
  
**2023/9/22**  
  
深信服监测到用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞信息。  
  
  
**2023/9/22**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaPxATX7cO7sA0QU3B2VngsCYvGv5jOTBibZ4mibgnrNic0rWgwM3nFfJDw/640?wx_fmt=jpeg "")  
  
  
  
