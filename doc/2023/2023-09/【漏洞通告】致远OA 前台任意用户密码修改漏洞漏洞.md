#  【漏洞通告】致远OA 前台任意用户密码修改漏洞漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-09-08 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1WeA2yENFJicvVsYVI9NzGtIG3bzD6bG2IZraLuRkUg1qONicWEcEGJFpQ/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
致远OA 前台任意用户密码修改漏洞  
  
**组件名称：**  
  
致远OA   
  
**影响范围：**  
  
V5/G6 V8.1SP2、V8.2  
  
**漏洞类型：**  
  
密码修改  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可修改用户密码。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1WdHnLg5hss9xLG8SbuUzJdlnV6lqgRhvkXReFLngB7JZPvrbPNkjFrA/640?wx_fmt=gif "")  
  
**组件介绍**  
  
致远OA是一款企业级办公自动化软件，它提供了一系列的办公自动化解决方案，包括文档管理、流程管理、协同办公、知识管理、人力资源管理等功能。致远OA可以帮助企业实现信息化管理，提高工作效率和管理水平，同时也可以提高企业的竞争力。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1WdHnLg5hss9xLG8SbuUzJdlnV6lqgRhvkXReFLngB7JZPvrbPNkjFrA/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年9月8日，深信服安全团队监测到一则致远OA组件存在任意密码修改漏洞的信息，漏洞编号：暂无，漏洞威胁等级：高危。  
  
  
该漏洞是由于致远OA修改用户密码时收发验证码的接口存在缺陷，**攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行未授权重置密码攻击，最终越权登录账号并可能进一步实现远程代码执行。**  
  
  
**影响范围**  
  
目前受影响的致远OA版本：  
  
    V5/G6 V8.1SP2、V8.2  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1WdHnLg5hss9xLG8SbuUzJdlnV6lqgRhvkXReFLngB7JZPvrbPNkjFrA/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81&id=171  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1WdHnLg5hss9xLG8SbuUzJdlnV6lqgRhvkXReFLngB7JZPvrbPNkjFrA/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对致远OA的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**预计 2023 年9月 10日发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对致远OA 前台任意用户密码修改漏洞的主动扫描，可**批量快速检出**业务场景中是否存在**漏洞风险**，相关产品如下：  
  
**【深信服云镜YJ】**预计2023年9月10日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年9月10日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月10日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月10  
  
支持对致远OA 前台任意用户密码修改漏洞的监测，  
  
日发布检测方案。  
  
  
**3.漏洞安全监测**  
  
支持对通达OA SQL注入事件的监测，可依据流量收集**实时监控**业务场景中的**受影响资产情况，快速检查受影响范围**，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2023年9月10日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月10日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月10日发布检测方案。  
  
****  
  
**4.漏洞安全防护**  
  
支持对通达OA SQL注入漏洞的防御，**可阻断攻击者针对该事件的入侵行为**，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2023年9月10日发布防护方案。  
  
**【深信服Web应用防火墙WAF】**预计2023年9月10日发布防护方案。  
  
**【深信服安全托管服务MSS】**预计2023年9月10日发布防护方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年9月10日发布防护方案。  
  
  
**参考链接**  
  
  
https://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81&id=171  
  
  
**时间轴**  
  
  
  
**2023/9/8**  
  
深信服监测到致远OA 前台任意用户密码修改漏洞攻击信息。   
  
  
**2023/9/8**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1WF0QCG5LorfGxcWzxlfQB6x8Tu9RqIZ4R8ZEd8NgrhX3xL6wsbB5OvA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zg3xZBibTI8bJ2NbPnoqV1Waar3jJrSHhX67rwtzENybzmOBxq4LbkJ56EnCZhbepLiauuLcv5QejQ/640?wx_fmt=jpeg "")  
  
  
  
