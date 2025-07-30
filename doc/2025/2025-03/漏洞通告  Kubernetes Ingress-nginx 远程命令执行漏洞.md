#  漏洞通告 | Kubernetes Ingress-nginx 远程命令执行漏洞   
原创 微步情报局  微步在线研究响应中心   2025-03-27 12:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
Ingress-nginx Admission Controller 是 Ingress-nginx 的一个重要组件，它是一种准入控制器 (Admission Controller)，负责在 Kubernetes 集群中对 Ingress 资源和其他相关的资源进行验证和修改，从而确保 Ingress 的配置符合最佳实践，并增强安全性。  
  
近日，微步情报局监控到Wiz Research 团队披露IngressNightmare系列漏洞（ CVE-2025-1097、CVE-2025-1098、CVE-2025-24514、CVE-2025-1974），未经身份验证的攻击者可利用上述漏洞在Ingress-nginx Admission Controller的上下文中实现任意代码执行，进而可获取敏感数据并接管集群。  
  
该漏洞技术细节已公开，危害较大，建议受影响的客户尽快修复。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody><tr style="outline: 0px;height: 31.0667px;"><td rowspan="3" data-colwidth="110" width="110" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><strong style="outline: 0px;"><span leaf=""><span textstyle="" style="font-weight: normal;">基本信息</span></span></strong></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="189" width="186" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">微步编号</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-weight: normal;">XVE-2025-</span></span><span leaf=""><span textstyle="" style="font-weight: normal;">6984</span></span></span></p></td></tr><tr><td data-colwidth="189" style="border-left-color: rgb(191, 191, 191);border-left-width: 0.666667px;border-top-color: rgb(191, 191, 191);border-top-width: 0.666667px;"><span style="color: rgb(84, 84, 84);font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">CVE编号</span></span></span></td><td data-colwidth="261" style="border-left-color: rgb(191, 191, 191);border-left-width: 0.666667px;border-top-color: rgb(191, 191, 191);border-top-width: 0.666667px;"><span style="color: rgb(84, 84, 84);font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">CVE-2025-</span></span><span leaf=""><span textstyle="" style="font-weight: normal;">1974</span></span></span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td data-colwidth="189" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-weight: normal;">漏洞类型</span></span></span></td><td data-colwidth="261" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-weight: normal;">远程代码执行</span></span></span></p></td></tr><tr style="outline: 0px;height: 31.0667px;"><td rowspan="5" data-colwidth="110" width="135" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">利用条件评估</span></span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="189" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">利用漏洞的网络条件</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-weight: normal;">远程</span></span></span></td></tr><tr style="outline: 0px;height: 31.0667px;"><td data-colwidth="189" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-weight: normal;">是否需要绕过安全机制</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-weight: normal;">不需要</span></span></span></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="189" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">对被攻击系统的要求</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(219, 0, 0);"><span leaf=""><span textstyle="" style="font-weight: normal;">Admission webhook对外开放</span></span></span></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="189" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-weight: normal;">利用漏洞的权限要求</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-weight: normal;">无需权限</span></span></span></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="189" width="189" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">是否需要受害者配合</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-weight: normal;">否</span></span></span></td></tr><tr style="outline: 0px;height: 27.2px;"><td rowspan="2" data-colwidth="110" width="115" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">利用情报</span></span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="189" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-weight: normal;">POC是否公开</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="261" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;"><span leaf=""><span textstyle="" style="color: rgb(219, 0, 0);font-weight: normal;">是</span></span></span></td></tr><tr style="padding-right: 7.2px;padding-left: 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td data-colwidth="189" width="169" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;"><span leaf=""><span textstyle="" style="font-weight: normal;">已知利用行为</span></span><span leaf=""><br/></span></span></td><td data-colwidth="261" width="222" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27px;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-weight: normal;">否</span></span></span></td></tr></tbody></table>  
****  
**漏洞影响范围**  
  
  
  
<table><tbody><tr style="outline: 0px;height: 33.2px;"><td data-colwidth="172" width="152" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">产品名称</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="346" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf="">Kubernetes &gt; Ingress-nginx</span></span></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="172" width="172" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">受影响版本</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="346" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">version ≤ 1.11.4，1.12.0 受影响</span></span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;"></span></p></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="172" width="172" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">影响范围</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="346" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="letter-spacing: 0.578px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf="">有</span></span></td></tr></tbody></table>  
  
**漏洞复现**  
  
  
  
  
通过 CVE-2025-24514 + CVE-2025-1974 实现RCE：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKRfkOibMss786PqPwUGjHu4s07TDUFZ8H0AloGHFuZfBBLLLiaRAKxH1J9pykvqZV8CgqGcaaBtc8w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKRfkOibMss786PqPwUGjHu48WicGAdPUiaSqibhbDFW3VZoDCZoIRRVLELhcxlmknuc10AhLicdicI1xXg/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
官方已发布修复方案，建议受影响的客户升级到1.11.5或1.12.1。  
  
https://github.com/kubernetes/ingress-nginx/releases/tag/controller-v1.11.5  
  
https://github.com/kubernetes/ingress-nginx/releases/tag/controller-v1.12.1  
  
## 临时修复方案：  
  
1. 设置IP白名单，只允许Kubernetes API Server能够访问admission controller。  
  
2.   
结合业务情况，临时禁止Ingress-nginx的Admission Controller组件  
，配置方式如下：  
- 如果使用Helm安装，重新安装时设置controller.admissionWebhooks.enabled=false  
  
- 如果手动安装：删除名为  
ingress-nginx-admission  
的  
ValidatingWebhookConfiguration  
，并从  
ingress-nginx-controller  
容器的  
Deployment  
或  
DaemonSet  
中移除  
--validating-webhook  
参数。  
  
**参考链接**  
  
  
- https://github.com/kubernetes/kubernetes/issues/131009  
  
- https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
  
  
