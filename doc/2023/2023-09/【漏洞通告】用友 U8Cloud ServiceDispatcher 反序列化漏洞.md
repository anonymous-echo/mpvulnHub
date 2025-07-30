#  【漏洞通告】用友 U8Cloud ServiceDispatcher 反序列化漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-09-22 16:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaHukgUnn52zJvjP4WQ9Gl0op1VIlPUJgnUxRRfxnfMUpic7MLXZvB4fQ/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
用友 U8Cloud ServiceDispatcher 反序列化漏洞  
  
**组件名称：**  
  
用友 U8Cloud  
  
**影响范围：**  
  
用友 U8Cloud所有版本  
  
**漏洞类型：**  
  
未授权访问  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**组件介绍**  
  
用友U8Cloud是一款企业级ERP，用于协助企业实现业务协同和流程管理的高效化和数字化。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年9月22日，深信服安全团队监测到一则用友U8Cloud组件存在反序列化漏洞的信息，漏洞威胁等级：高危。  
  
该漏洞是由于用友U8Cloud对不安全的数据进行反序列化操作，**攻击者可利用该漏洞在未授权的情况下，发送构造好的恶意数据，远程执行代码。**  
  
  
**影响范围**  
  
目前受影响的用友U8Cloud版本：  
  
全版本  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://security.yonyou.com/#/patchInfo?foreignKey=7bd5b43e2c984a618b2b1d3f288110ae  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaoWMy5b2PO8M37c5Vh4EDE0LZC2HAys6HA8RmkhPr7RtoLYIwdK0FBA/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对用友U8Cloud组件的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对用友U8Cloud反序列化漏洞的主动检测，可**批量快速检出**业务场景中是否存在**漏洞风险**，相关产品如下：  
  
**【深信服云镜YJ】**预计2023年9月24日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年9月25日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月24日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月24日发布检测方案。  
  
  
**参考链接**  
  
  
https://security.yonyou.com/#/patchInfo?foreignKey=7bd5b43e2c984a618b2b1d3f288110ae  
  
  
**时间轴**  
  
  
  
**2023/9/22**  
  
深信服监测到用友 U8Cloud ServiceDispatcher 反序列化漏洞信息。  
  
  
**2023/9/22**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3Niam7tgqe3InlhGuUTicQmldJuo2nnjoJX40kB82ebcOOjxibjCDD2E0XRQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yUt7qWiaWLnABNtdIY4G3NiaPxATX7cO7sA0QU3B2VngsCYvGv5jOTBibZ4mibgnrNic0rWgwM3nFfJDw/640?wx_fmt=jpeg "")  
  
  
  
