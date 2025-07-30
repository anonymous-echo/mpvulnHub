#  【漏洞通告】畅捷通T+ SQL注入漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-06-15 20:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEN1TEK9qgXw6RMicw91jF6LiaxIX2V4laEaOrdNZ3hoxbyhUHVx8qzRAw/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
畅捷通T+ SQL注入漏洞  
  
**组件名称：**  
  
畅捷通T+  
  
**影响范围：**  
  
畅捷通T+ 13.0  
  
畅捷通T+ 16.0  
  
**漏洞类型：**  
  
SQL注入  
  
**利用条件：**  
  
1、用户认证：不需要  
  
2、前置条件：未知  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可利用。  
  
<综合评定威胁等级>：高危，能造成代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEfLA54NMeRqvOX7w9opZx4MUqkQ3YjErRtPwhuIB88cqKDAibLHUu1Yg/640?wx_fmt=gif "")  
  
**组件介绍**  
  
畅捷通T+是一款灵动、智慧、时尚的互联网管理软件，主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEfLA54NMeRqvOX7w9opZx4MUqkQ3YjErRtPwhuIB88cqKDAibLHUu1Yg/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年6月15日，深信服安全团队监测到一则畅捷通T+组件存在SQL注入漏洞的信息，漏洞威胁等级：高危。  
  
畅捷通T+存在SQL注入漏洞，**攻击者可利用此漏洞在未授权的情况下执行任意SQL语句，最终造成服务器敏感性信息泄露或远程命令执行。**  
  
  
**影响范围**  
  
目前受影响的版本：  
  
畅捷通T+ 13.0  
  
畅捷通T+ 16.0  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEfLA54NMeRqvOX7w9opZx4MUqkQ3YjErRtPwhuIB88cqKDAibLHUu1Yg/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布安全补丁，建议受影响的用户及时联系产商安装安全补丁。链接如下：  
  
https://www.chanjetvip.com/product/goods/  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEfLA54NMeRqvOX7w9opZx4MUqkQ3YjErRtPwhuIB88cqKDAibLHUu1Yg/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对畅捷通T+组件 的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
【**深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞安全监测**  
  
支持对畅捷通T+ SQL注入漏洞攻击事件的监测，可依据流量收集**实时监控**业务场景中的**受影响资产**情况，快速检查受影响范围，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2023年6月19日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年6月19日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年6月19日发布检测方案。  
  
  
**3.漏洞安全防护**  
  
支持对畅捷通T+ SQL注入漏洞攻击事件的防御，**可阻断攻击者针对该事件的入侵行为**，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2023年6月19日发布防护方案。  
  
**【深信服Web应用防火墙WAF】**预计2023年6月19日发布防护方案。  
  
**【深信服安全托管服务MSS】**预计2023年6月19日发布防护方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年6月19日发布防护方案。  
  
  
**时间轴**  
  
  
  
**2023/6/15**  
  
深信服监测到畅捷通T+ SQL注入漏洞的攻击信息。  
  
  
**2023/6/15**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEyG9H84xRmP3LNibewibqecibRzXyQV2XWOKHdZfukk0ibusKfWa8HictmibQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zRxX3tHd95gfibiaAFcibTjqEkeRyBXgRq0PP5G9HJQQna39fStTsT6mU1xjdygYJOunCyuS9cy1bMw/640?wx_fmt=jpeg "")  
  
  
  
