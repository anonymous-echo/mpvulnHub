#  【漏洞通告】Showdoc远程代码执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2024-05-29 16:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yHHx2DlGgDPxTEQX44UJkmcwbX70elicOPGGCwlibKv502jfO1aAqEE4VsSx4EvdKmCI8K7xFdFCRA/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
Showdoc远程代码执行漏洞  
  
**组件名称：**  
  
Showdoc  
  
**影响范围：**  
  
Showdoc < 3.2.5  
  
**漏洞类型：**  
  
代码注入  
  
**利用条件：**  
  
1、用户认证：不需要用户认证  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，能造成远程代码执行。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yHHx2DlGgDPxTEQX44UJkmNibeicgd8pENjIBVYTGCxbSsicOI6hQ3P0hBgZqka5q1H74BJ28D9lZpQ/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
Showdoc是一款在线文档工具，支持Markdown语法，可以用于快速记录、分享和协作文档。它拥有简洁的界面和丰富的功能，包括在线编辑、多人协作、讨论评论、版本管理、权限管理等特性。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yHHx2DlGgDPxTEQX44UJkmNibeicgd8pENjIBVYTGCxbSsicOI6hQ3P0hBgZqka5q1H74BJ28D9lZpQ/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
  
2024年5月29日，深瞳漏洞实验室监测到一则Showdoc组件存在代码注入漏洞的信息，漏洞威胁等级：高危。  
  
Showdoc存在远程代码执行漏洞，**攻击者通过SQL注入漏洞获取到token进入后台，进入后台后可结合反序列化漏洞，写入WebShell，从而获取服务器权限。**  
  
  
**影响范围**  
  
目前受影响的Showdoc版本：  
  
Showdoc < 3.2.5  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yHHx2DlGgDPxTEQX44UJkmNibeicgd8pENjIBVYTGCxbSsicOI6hQ3P0hBgZqka5q1H74BJ28D9lZpQ/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
官方已发布最新的3.2.5版本修复该漏洞。受影响客户请尽快更新。链接：https://github.com/star7th/showdoc  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yHHx2DlGgDPxTEQX44UJkmNibeicgd8pENjIBVYTGCxbSsicOI6hQ3P0hBgZqka5q1H74BJ28D9lZpQ/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**风险资产发现**  
  
支持对 showdoc的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**参考链接**  
  
  
https://github.com/star7th/showdoc  
  
  
**时间轴**  
  
  
  
**2024/5/29**  
  
深瞳漏洞实验室监测到Showdoc远程代码执行漏洞信息。  
  
  
**2024/5/29**  
  
深瞳漏洞实验室发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yHHx2DlGgDPxTEQX44UJkmG8aaIwf2qnraCvLWJ8KicqdpseYAB6oW5MQe4CholEL5ILYKRAcicc3Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zvcIHbwGGYKbqDVYsVKzNNia1jYtHf49C7133AlDXAgex2W4lFvpia56tjQQDkiauNBrl08YbxqG01A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
