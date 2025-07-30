#  【漏洞通告】XXL-JOB 默认accessToken 认证绕过漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-11-01 18:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88Lqp5RnkichxBFwcRmBIpdKKia6ib3nvqLTmlXyYDnx9neUX2VEwPdLrnUQ/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
XXL-JOB 默认accessToken 认证绕过漏洞  
  
**组件名称：**  
  
XXL-JOB  
  
**影响范围：**  
  
XXL-JOB <= 2.4.0  
  
**漏洞类型：**  
  
认证绕过  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权。  
  
<综合评定威胁等级>：高危，能造成认证绕过。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88L6Lx1yiasBxVMM2nTFpd9UGTREGQdcPiaDTZqx6KI338qUgkuQN61o9Qw/640?wx_fmt=gif "")  
  
**组件介绍**  
  
XXL-JOB 是一款开源的分布式任务调度平台，用于实现大规模任务的调度和执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88L6Lx1yiasBxVMM2nTFpd9UGTREGQdcPiaDTZqx6KI338qUgkuQN61o9Qw/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年11月1日，深瞳漏洞实验室监测到一则XXL-JOB组件存在认证绕过漏洞的信息，漏洞威胁等级：高危。  
  
该漏洞是由于XXL-JOB 在默认配置下，用于调度通讯的 accessToken 不是随机生成的，而是使用 application.properties 配置文件中的默认值，如果用户没有修改该默认值，**攻击者可利用该默认值在未授权的情况下绕过认证，最终可导致远程代码执行。**  
  
  
**影响范围**  
  
目前受影响的XXL-JOB版本：  
  
XXL-JOB <= 2.4.0  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88L6Lx1yiasBxVMM2nTFpd9UGTREGQdcPiaDTZqx6KI338qUgkuQN61o9Qw/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布修复建议，建议受影响的用户及时修改调度中心和执行器配置项 xxl.job.accessToken 的默认值。官方文档链接如下：  
  
https://www.xuxueli.com/xxl-job/#5.10%20%E8%AE%BF%E9%97%AE%E4%BB%A4%E7%89%8C%EF%BC%88AccessToken%EF%BC%89  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88L6Lx1yiasBxVMM2nTFpd9UGTREGQdcPiaDTZqx6KI338qUgkuQN61o9Qw/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对 XXL-JOB 组件的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**参考链接**  
  
  
https://x.threatbook.com/v5/article?threatInfoID=96052  
  
  
**时间轴**  
  
  
  
**2023/11/1**  
  
深瞳漏洞实验室监测到XXL-JOB默认 accessToken 认证绕过漏洞攻击信息。  
  
  
**2023/11/1**  
  
深瞳漏洞实验室发布漏洞通告。  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88Ly2kPl9PIOicTlJbbjcaqibnyWfy8MxhTLibTT2sUaoLndU7V6iaybI3fkQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zmwMXtJDTOdpPxbCF9B88LEBXmQF09icmm7SyTY7u6dsHGWx6lP2Q24WkTIKQXSkVdic0icmX0FYbYA/640?wx_fmt=jpeg "")  
  
  
  
