> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5MTc3ODY4Mw==&mid=2247507850&idx=1&sn=92e3b86bb828888ef9f72653adc6c80c

#  漏洞通告 | 用友YonBIP（R6旗舰版）任意用户密码重置漏洞  
原创 微步情报局  微步在线研究响应中心   2025-07-16 01:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png "")  
  
  
**漏洞概况**  
  
  
  
用友YonBIP R6 旗舰版是用友推出的全球领先的企业数智化平台与应用软件，旨在帮助企业实现数字化转型，成就数智企业。  
  
微步漏洞团队通过X漏洞奖励计划获取到用友YonBIP R6旗舰版任意用户密码重置漏洞情报（https://x.threatbook.com/v5/vul/XVE-2025-25494）。  
由于密码重置功能设计缺陷，导致攻击者可绕过邮箱验证码，直接重置用户密码。  
该漏洞利用方式简单  
，  
建议受影响用户尽快修复  
。  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：****高**  
  
<table><tbody><tr><td rowspan="2" data-colwidth="123" valign="middle"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);font-weight: bold;">基本信息</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">微步编号</span></span></section></td><td data-colwidth="191"><p data-pm-slice="0 0 []"><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><font face="微软雅黑"><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">XVE-2025-25494</span></span></font></span></p></td></tr><tr><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">漏洞类型</span></span></section></td><td data-colwidth="191"><section><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">逻辑缺陷</span></span></section></td></tr><tr><td rowspan="5" data-colwidth="123" valign="middle"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);font-weight: bold;">利用条件评估</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">利</span></span><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">用漏洞的网络条</span></span><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">件</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">远程</span></span></section></td></tr><tr><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">是否需要绕过安全机制</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">不需要</span></span></section></td></tr><tr><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">对被攻击系统的需求</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">默认配置</span></span></section></td></tr><tr><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">利用漏洞的权限要求</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">无需权限</span></span></section></td></tr><tr><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">是否需要受害者配合</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">否</span></span></section></td></tr><tr><td rowspan="2" data-colwidth="123"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);font-weight: bold;">利用情报</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">POC是否公开</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">否</span></span></section></td></tr><tr><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">已知利用行为</span></span></section></td><td data-colwidth="191"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">否</span></span></section></td></tr></tbody></table>  
****  
**漏洞影响范围**  
  
  
  
  
<table><tbody><tr><td data-colwidth="122"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);font-weight: bold;">产品名称</span></span></section></td><td data-colwidth="391"><p data-pm-slice="0 0 []"><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">用</span></span><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">友网络科技股份有</span></span><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">限公</span></span><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">司</span></span><font face="微软雅黑"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">- YonBIP R6旗舰版</span></span></font></p></td></tr><tr><td data-colwidth="122"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);font-weight: bold;">受影响版本</span></span></section></td><td data-colwidth="391"><p data-pm-slice="0 0 []"><span leaf="" style="text-align: left;justify-content: flex-start;outline: 0px;"><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">YonBIP V3.0(R6_2407)</span></span></p></td></tr><tr><td data-colwidth="122"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);font-weight: bold;">有无修复补丁</span></span></section></td><td data-colwidth="391"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(63, 63, 63);">有</span></span></section></td></tr></tbody></table>  
漏洞复现  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMINWyOdytLcq44VkeevlK7Q3lDnbXpHn2Zfzu4JicaxqDxdjEjYAAgpd0bwCyPQM3a5vQTibQ1pBVcA/640?wx_fmt=png&from=appmsg "")  
  
**修复方案**  
  
  
  
官方修复方案  
  
用友安全中心已发布漏洞公告，请尽快前往下载补丁进行更新：  
  
https://security.yonyou.com/#/noticeInfo?id=709  
  
临时缓解措施  
- 可配置防护策略，限制访问漏洞相关路径。完整漏洞利用路径请通过微步漏洞情报查询。  
  
- 如非必要，避免将资产暴露在互联网。  
  
**微步产品侧支持情况**  
  
  
- 微步威胁感知平台TDP  
 已支持检测，检测ID：S3100164693，模型/规则高于20250715000000可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMINWyOdytLcq44VkeevlK7QWcQLuQXQ7TVAdcPia3JOly2BMKrUuvmaonCYWTrzFaBlYWibvW0OpmpQ/640?wx_fmt=png&from=appmsg "")  
  
- END -  
  
  //    
  
**微步漏洞情报订阅服务**  
  
  
微步提供漏洞情报订阅服务，精准、高效助力企业漏洞运营：  
- 提供高价值漏洞情报，具备及时、准确、全面和可操作性，帮助企业高效应对漏洞应急与日常运营难题；  
  
- 可实现对高威胁漏洞提前掌握，以最快的效率解决信息差问题，缩短漏洞运营MTTR；  
  
- 提供漏洞完整的技术细节，更贴近用户漏洞处置的落地；  
  
- 将漏洞与威胁事件库、APT组织和黑产团伙攻击大数据、网络空间测绘等结合，对漏洞的实际风险进行持续动态更新  
。  
  
  
扫码在线沟通  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png "")  
  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzI5NjA0NjI5MQ==&mid=2650184178&idx=1&sn=42c6b4bb8e2a1d95c686725b2159bc97&scene=21#wechat_redirect)  
  
