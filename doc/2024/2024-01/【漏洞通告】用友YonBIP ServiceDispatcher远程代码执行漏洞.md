#  【漏洞通告】用友YonBIP ServiceDispatcher远程代码执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2024-01-26 16:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUpJMZ7uw9UhnzVnFbLFick9acx8TUVZlKpiajJhay6f6LEd6ZoECwj5Ow/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
用友YonBIP ServiceDispatcher远程代码执行漏洞  
  
**组件名称：**  
  
用友YonBIP  
  
**影响范围：**  
  
YonBIP高级版2207（未安装对应补丁）  
  
**漏洞类型：**  
  
远程代码执行  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可远程代码执行。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUY4JfSwvd1dI9lDHkCCvBicjtM0z7gwMrXkk1wpxjF3Kozs8wujQS0zA/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
YonBIP是用友采用新一代信息技术，按照云原生（含微服务）、元数据驱动、中台化和数用分离的架构设计，涵盖平台服务、应用服务、业务服务与数据服务等形态，集工具、能力和资源服务为一体，服务企业与产业商业创新的平台型、生态化的云服务群。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUY4JfSwvd1dI9lDHkCCvBicjtM0z7gwMrXkk1wpxjF3Kozs8wujQS0zA/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
2024年1月26日，深瞳漏洞实验室监测到一则用友YonBIP存在远程代码执行漏洞的信息，漏洞威胁等级：高危。  
  
该漏洞是由于安全控制不严格，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行远程代码执行攻击，最终获取服务器权限。  
  
  
**影响范围**  
  
目前受影响的用友YonBIP版本：  
  
YonBIP高级版2207（未安装对应补丁）  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUY4JfSwvd1dI9lDHkCCvBicjtM0z7gwMrXkk1wpxjF3Kozs8wujQS0zA/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://security.yonyou.com/#/noticeInfo?id=476  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUY4JfSwvd1dI9lDHkCCvBicjtM0z7gwMrXkk1wpxjF3Kozs8wujQS0zA/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对用友YonBIP 的主动检测，可**批量检出**业务场景中该事件的受影响资产情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
**【深信服漏洞评估工具TSS】**已发布资产检测方案。  
  
****  
**2.漏洞主动扫描**  
  
支持对用友YonBIP ServiceDispatcher远程代码执行漏洞的主动扫描，可**批量快速检出**业务场景中是否存在漏洞风险，相关产品如下：  
  
**【深信服云镜YJ】**已发布扫描方案。  
  
**【深信服漏洞评估工具TSS】**已发布扫描方案。  
  
**【深信服安全托管服务MSS】**已发布扫描方案,（需要具备TSS组件能力）。  
  
**【深信服安全检测与响应平台XDR】**已发布扫描方案,（需要具备云镜组件能力）。  
  
  
**参考链接**  
  
  
https://security.yonyou.com/#/noticeInfo?id=476  
  
  
**时间轴**  
  
  
  
**2024/1/26**  
  
深瞳漏洞实验室监测到用友YonBIP ServiceDispatcher远程代码执行漏洞攻击信息。  
  
  
**2024/1/26**  
  
深瞳漏洞实验室发布漏洞通告。  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUq1ibZYOp6bylHJdy78lNFFUkVKtW7KXnINr5hNClzKicpHW4b2icETUKQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zvN6n2ziaDfy82IM1SU8WTUuZXnpKHyAia8Vg0euKTEE5MHYuoP0KmadQvesDupvqfc1Mqg9sMEZ9w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
