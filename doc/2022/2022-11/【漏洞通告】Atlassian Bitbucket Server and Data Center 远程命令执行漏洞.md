#  【漏洞通告】Atlassian Bitbucket Server and Data Center 远程命令执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2022-11-23 19:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFD66FVHPtz30u0C4HhTIYBualvYEDia5Lib5PQtianlnvHNr0VUodFstibA/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
Atlassian Bitbucket Server and Data Center 远程命令执行漏洞  
  
**组件名称：**  
  
Atlassian Bitbucket Server and Data Center  
  
**影响范围：**  
  
7.0.0 ≤ Atlassian Bitbucket Server and Data Center ＜ 7.6.19  
  
7.7.0 ≤ Atlassian Bitbucket Server and Data Center < 7.17.12  
  
7.18.0 ≤ Atlassian Bitbucket Server and Data Center < 7.21.6  
  
7.22.0 ≤ Bitbucket Server and Data Center < 8.0.5  
  
**漏洞类型：**  
  
远程命令执行  
  
**利用条件：**  
  
1、用户认证：不需要用户认证（开启Allow public signup）2、前置条件：默认配置3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：未知  
。  
  
<综合评定威胁等级>：严重，  
能造成远程命令执行。  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFS2bajdJXxSuFlgztV9ib1hiakwzmLlHUQpX2kxibJO5tiaV9piaQptz4cVw/640?wx_fmt=gif "")  
  
**组件介绍**  
  
Atlassian Bitbucket Data Center是Atlassian推出的一款现代化代码协作平台，支持代码审查、分支权限管理、CICD等功能。同时也是大规模构建优质软件。使用Bitbucket Data Center的智能镜像功能，可以缩短克隆时间并减少CI构建造成的拥塞。使用Data Center的迁移工具可降低管理多个实例的管理开销。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFS2bajdJXxSuFlgztV9ib1hiakwzmLlHUQpX2kxibJO5tiaV9piaQptz4cVw/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
2022年11月22日，深信服安全团队监测到一则 Atlassian Bitbucket Server and Data Center 组件存在远程命令执行漏洞的信息，漏洞编号：CVE-2022-43781，漏洞威胁等级：严重。  
  
  
该漏洞是由于环境变量存在命令注入漏洞，**开启 Allow public signup 功能下，攻击者可利用该漏洞在未授权情况下，构造恶意数据进行远程命令注入攻击，最终获取服务器最高权限。**  
  
  
**影响范围**  
  
目前受影响的 Atlassian Bitbucket Server and Data Center 版本：  
  
7.0.0 ≤ Atlassian Bitbucket Server and Data Center < 7.6.19  
  
7.7.0 ≤ Atlassian Bitbucket Server and Data Center < 7.17.12  
  
7.18.0 ≤ Atlassian Bitbucket Server and Data Center < 7.21.6  
  
7.22.0 ≤ Atlassian Bitbucket Server and Data Center < 8.0.5  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFS2bajdJXxSuFlgztV9ib1hiakwzmLlHUQpX2kxibJO5tiaV9piaQptz4cVw/640?wx_fmt=gif "")  
  
**如何检测组件系统版本**  
  
访问登陆页面，即可查看当前版本号。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFzeYsl7ic9qgcej545rcffFzPCrqL3bFbApfZ0LibibbLb109AibCwjUxvw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFS2bajdJXxSuFlgztV9ib1hiakwzmLlHUQpX2kxibJO5tiaV9piaQptz4cVw/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://www.atlassian.com/software/bitbucket/download-archives  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFS2bajdJXxSuFlgztV9ib1hiakwzmLlHUQpX2kxibJO5tiaV9piaQptz4cVw/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
**1.主动检测**  
  
支持对Atlassian Bitbucket Server and Data Center远程命令执行漏洞CVE-2022-43781的主动检测，可批量快速检出业务场景中该事件的受影响资产情况，相关产品如下：  
  
**【深信服云镜YJ】**预计2022年11月30日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2022年11月30日发布检测方案。  
  
**【深信服主机安全检测响应平台CWPP】**预计2022年12月2日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2022年11月30日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2022年11月30日发布检测方案。  
  
  
**参考链接**  
  
https://confluence.atlassian.com/bitbucketserver/bitbucket-server-and-data-center-security-advisory-2022-11-16-1180141667.html  
  
  
**时间轴**  
  
  
  
**2022/11/22**  
  
深信服监测到官方发布安全补丁。  
  
  
**2022/11/23**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfF9bteawJY7ibYw2KCdjdQiadMzH1RsjJuiaF1hrKmcQk1p4IeYf7LChZXQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yfe7HN062Qib9XKiceuJKOfFhLXvWEPxTUJ6VjwpZjkKiarOTIqcSDXeO7hV7M8JH3CibqdwiarHsMjFw/640?wx_fmt=jpeg "")  
  
  
  
