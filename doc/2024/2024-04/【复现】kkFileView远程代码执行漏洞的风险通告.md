#  【复现】kkFileView远程代码执行漏洞的风险通告   
原创 赛博昆仑CERT  赛博昆仑CERT   2024-04-18 17:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaZ7t7b9Dodvib7ddpGMC6vx4COAy4sBoGbGCkwVUIJSHBPI0z1Utrp1h5ys6ygT3albl3PgjejJcRRRiaDFFbMBA/640?wx_fmt=gif "")  
  
  
-  
赛博昆仑漏洞安全通告-  
  
kkFileView远程代码执行漏洞的风险通告   
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/7j1UQofaR9fsNXgsOXHVKZMJ1PCicm8s4RHQVjCJEjX63AsNibMx3So4wSMAvubEOoU2vLqYY7hIibIJbkEaPIDs5A4ianh5jibxw/640?wx_fmt=svg "")  
  
  
  
****  
**漏洞描述**  
  
kkFileView为文件文档在线预览解决方案，该项目使用流行的spring boot搭建，易上手和部署，基本支持主流办公文档的在线预览，如doc,docx,xls,xlsx,ppt,pptx,pdf,txt,zip,rar,图片,视频,音频等等  
  
近日，赛博昆仑CERT监测到 kkFileView远程代码执行漏洞的漏洞情报，攻击者可利用该漏洞上传恶意压缩包并覆盖文件，随后可利用被覆盖的文件执行任意代码来获取系统权限。  
<table><tbody><tr><td valign="top" style="border-width: 1pt;border-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞名称</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top-width: 1pt;border-color: rgb(221, 221, 221);border-right-width: 1pt;border-bottom-width: 1pt;border-left-width: initial;border-left-style: none;padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">kkFileView</span>远程代码执行漏洞<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞公开编号</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">暂无<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>昆仑漏洞库编号</strong><o:p></o:p></span></p></td><td colspan="3" valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">CYKL-2024-006850</span><o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞类型</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">代码执行</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="148"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>公开时间</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="133"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><span lang="EN-US" style="color: rgb(0, 122, 170);font-family: Arial, sans-serif;">2024-04-16</span><o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞等级</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">高危</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="148"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>评分</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="133"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">暂无<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞所需权限</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">无权限要求</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="148"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞利用难度</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="133"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">低<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong><span lang="EN-US" style="font-family: Arial, sans-serif;">PoC</span></strong><strong>状态</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">已公开</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="148"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong><span lang="EN-US" style="font-family: Arial, sans-serif;">EXP</span></strong><strong>状态</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="133"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">已公开<o:p></o:p></span></p></td></tr><tr><td valign="top" style="border-right-width: 1pt;border-color: rgb(221, 221, 221);border-bottom-width: 1pt;border-left-width: 1pt;border-top-width: initial;border-top-style: none;padding: 3pt 6pt 1.5pt;" width="169"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>漏洞细节</strong><o:p></o:p></span></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="127"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">已公开</span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;" width="148"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);"><strong>在野利用</strong></span><o:p></o:p></p></td><td valign="top" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-width: 1pt;border-bottom-color: rgb(221, 221, 221);border-right-width: 1pt;border-right-color: rgb(221, 221, 221);padding: 3pt 6pt 1.5pt;word-break: break-all;" width="133"><p style="margin: 6pt 0cm;line-height: 17.6px;font-size: 11pt;font-family: DengXian;"><span style="color: rgb(0, 122, 170);">未知</span><span style="background-color: rgb(255, 255, 255);color: rgb(91, 91, 91);font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;letter-spacing: 1.8px;text-align: left;text-indent: 2em;"></span></p></td></tr></tbody></table>  
  
  
**影响版本**  
  
  
4.2.0 <= kkFileView <= v4.4.0-beta  
  
**利用条件**  
  
  
使用默认配置。  
  
**漏洞复现**  
  
  
目前赛博昆仑CERT已确认漏洞原理，复现截图如下：  
  
复现版本为  
4.3.0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaZ7t7b9Dodus0AY7zlVxMiamPXH0PZ4XZdgMy4YdDbWvhP4RYjMJcGRibVeqSxGJ3Aia7MLlFS97oDIvtBRBib3XoQ/640?wx_fmt=png&from=appmsg "")  
  
**防护措施**  
  
  
- **临时缓解措施**  
  
开启 file.upload.disable=true 参数，禁用首页的文件上传功能。  
- **修复建议**  
  
目前，官方已发布修复建议，建议受影响的用户尽快升级至安全版本。  
  
下载地址：  
https://github.com/kekingcn/kkFileView/  
  
  
**技术咨询**  
  
赛博昆仑支持对用户提供轻量级的检测规则或热补方式，可提供定制化服务适  
配多种产品及规则，帮助用户进行漏洞检测和修复。  
  
赛博昆仑CERT已开启年订阅服务，付费客户(可申请试用)将获取更多技术详情，并支持适配客户的需求。  
  
联系邮箱：cert@cyberkl.com  
  
公众号：赛博昆仑CERT  
  
**参考链接**  
  
￮ https://github.com/kekingcn/kkFileView/commit/421a2760d58ccaba4426b5e104938ca06cc49778  
  
￮ https://github.com/kekingcn/kkFileView/  
  
**时间线**  
  
2024年04月17日，官方修复漏洞  
  
2024年04月18  
日，赛博昆仑CERT公众号  
发布漏洞风险通告  
  
  
  
  
