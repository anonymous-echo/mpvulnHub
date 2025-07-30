#  【漏洞通告】Google Chrome 类型混淆漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-06-06 20:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8w6BHNicFjfKia3Z34nGgibBbae7GvbudRarlNWkfW5NZ5roxibmfzgcWFw/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
Google Chrome类型混淆漏洞  
  
**组件名称：**  
  
Google Chrome  
  
**影响范围：**  
  
Google Chrome For Windows<114.0.5735.110  
  
Google Chrome For Linux or Mac<114.0.5735.106  
  
**漏洞类型：**  
  
类型混淆  
  
**利用条件：**  
  
1、用户认证：未知  
  
2、前置条件：未知  
  
3、触发方式：本地  
  
**综合评价：**  
  
<综合评定利用难度>：未知。  
  
<综合评定威胁等级>：高危，能造成代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**组件介绍**  
  
Google Chrome是一款由Google公司开发的网页浏览器，该浏览器基于其他开源软件撰写，包括WebKit，目标是提升稳定性、速度和安全性，并创造出简单且有效率的使用者界面。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2023年6月6日，深信服安全团队监测到一则Google Chrome组件存在类型混淆漏洞的信息，漏洞编号：CVE-2023-3079，漏洞威胁等级：高危。  
  
Google Chrome V8 JavaScript 引擎中存在类型混淆漏洞，此类漏洞通常会在成功读取或写入超出缓冲区边界的内存后导致浏览器崩溃或执行任意代码。  
  
  
**影响范围**  
  
目前受影响的版本：  
  
Google Chrome For Windows < 114.0.5735.110  
  
Google Chrome For Linux and Mac < 114.0.5735.106  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://www.google.com/chrome/  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8fdiaT8uDnKkUTcJHAyW284VebJ5TEoT7hGhjrQaNFm3ric6zOynibiaQpQ/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对Google Chrome的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
  
**参考链接**  
  
https://chromereleases.googleblog.com/2023/06/stable-channel-update-for-desktop.html  
  
  
**时间轴**  
  
  
  
**2023/6/6**  
  
深信服监测到Google Chrome组件存在类型混淆漏洞的漏洞信息。  
  
  
**2023/6/6**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8NtAZtiagkTsz0u9azppF5dfaBlm387IFogZibBEicAc2Z52qysotBBm3g/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yLJtEP6HkELh93nzGibKQw8nfiaicarHAN0MPAD458d47VOQE3OhiaFfuY3sAIqgvSSyBgqf9MomDUPg/640?wx_fmt=jpeg "")  
  
  
  
