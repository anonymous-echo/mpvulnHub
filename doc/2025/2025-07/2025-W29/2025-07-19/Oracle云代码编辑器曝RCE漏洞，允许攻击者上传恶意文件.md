> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247492816&idx=1&sn=6eb49110f0c5c62383b27221af9580ae

#  Oracle云代码编辑器曝RCE漏洞，允许攻击者上传恶意文件  
 信息安全大事件   2025-07-19 06:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5vQEM4wanuS6xRI4m1z333LzSzRjrgvAia6PYo7ngxNvzfxCibxlSJrjWvI3Eba4XHYjOcKmIic42FA/640?wx_fmt=png&from=appmsg "")  
  
Oracle云基础设施（OCI）代码编辑器近日被披露存在一个严重的远程代码执行（RCE）漏洞，攻击者可通过用户的一次点击操作，静默劫持其 Cloud Shell 环境。  
  
该漏洞目前已被修复，影响  
范围包括代码编辑器所集成的多个服务模块，如资源管理器（Resource Manager）、函数服务（Functions）和数据科学（Data Science），凸显了看似独立的云开发工具如何可能演变为攻击载体。  
  
要点概览  
  
1.Oracle Cloud 代码编辑器的文件上传功能缺乏跨站请求伪造（CSRF）防护，使得攻击者可通过“一键”方式上传恶意文件；  
  
2.该漏洞可实现远程代码执行，并可能危及多个 OCI 集成服务的安全；  
  
3.Oracle 已通过强制要求使用X-CSRF-Token 请求头来阻止跨域攻击。  
  
漏洞分析  
  
该漏洞源于Oracle 代码编辑器与 Cloud Shell 的深度集成：二者共享底层文件系统及用户会话上下文。这一设计缺陷使得攻击者可以在用户毫不知情的情况下，利用代码编辑器上传恶意文件至 Cloud Shell，并借助用户权限在环境中执行任意代码，从而完全控制受害者的云开发环境。  
  
尽管这种高度集成的设计初衷是为了为开发者提供无缝的使用体验，但实际上却无意中暴露出一个可被利用的攻击面，最终被安全研究人员发现并加以利用。  
  
Tenable 的研究始于一个简单的问题：既然开发人员可以轻松地通过代码编辑器上传文件，那么攻击者是否也能做到？这一思路最终导致研究人员发现了代码编辑器中的一个/file-upload 接口，该接口缺乏跨站请求伪造（CSRF）防护措施，这与 Cloud Shell 中已正确配置安全机制的上传接口形成鲜明对比。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5vQEM4wanuS6xRI4m1z33312n9DzbBWmM45icLh4OTDDUzqpGQzzGTaQpyflEPOsIQqjP91ML3Vug/640?wx_fmt=png&from=appmsg "")  
  
此次漏洞的核心组件是Cloud Shell 路由器（router.cloudshell.us-ashburn-1.oci.oraclecloud.com），该路由器接受包含 multipart/form-data 负载的 HTTP POST 请求。  
  
该路由器使用了配置为SameSite=None 属性的 CS-ProxyChallenge Cookie，未能对经过身份验证的用户发起的跨站请求提供有效防护。  
  
利用路径非常直接。攻击者可以创建恶意的HTML 页面，当经过身份验证的 OCI 用户访问该页面时，恶意文件会在用户不知情的情况下自动上传至其 Cloud Shell 环境。  
  
此次攻击采用了精心构造的HTTP 请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5vQEM4wanuS6xRI4m1z3334BZSibolZNjUCncK5urHywE5OGxy5UylDOUfz4zjq29v6jCyYRRugzw/640?wx_fmt=png&from=appmsg "")  
  
研究人员演示了攻击者如何覆盖.bashrc 文件，从而建立反向 shell，获得对 Cloud Shell 的交互式访问权限，并利用受害者的凭据通过 OCI CLI 实现对 OCI 服务的横向移动。  
  
防护措施  
  
针对该漏洞，Oracle 采取了额外的安全措施，特别是要求所有相关请求必须携带自定义 HTTP 头x-csrf-token，其值为 csrf-value。  
  
此项改动有效防止了CSRF 攻击，因为浏览器在跨源请求时无法自动附加自定义请求头，除非存在正确的 CORS 配置。  
  
该漏洞的影响不仅限于Cloud Shell，还波及到 Code Editor 的集成服务。由于这些服务运行在相同的共享文件系统上，恶意负载可能会影响 Resource Manager 工作区、Functions 部署以及 Data Science 环境，形成覆盖 OCI 开发者工具包的多重攻击面。  
  
此次事件凸显了云服务集成所带来的安全挑战，便利性功能在无意间扩大了攻击面，超出了其原本的设计范围。  
<table><tbody><tr><td data-colwidth="576"><p data-pm-slice="4 4 []" style="margin-bottom: 0px;"><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">江苏国骏可以为客户做的服务：</span></span></font></span><span style="font-family: 宋体;font-size: 10.5pt;"><span leaf=""><br/></span></span><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">云安全架构审计：进行</span></span></font></span><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">安全评估与咨询、安全策略与规划</span></span></font></span><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">工作</span></span></font></span></p><p data-pm-slice="0 0 []" style="margin-bottom: 0px;"><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">安全防护与加固：部署</span></span></font><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">Web应用防火墙（WAF）（安全网关产品）拦截恶意跨域请求；配置身份与访问控制安全产品，实施最小权限原则</span></span></font></span></p><p data-pm-slice="0 0 []" style="margin-bottom: 0px;"><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">安全监测与响应：通过安全智能产品监控异常文件上传行为；部署端点安全产品检测反向</span></span></font><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">Shell连接尝试，实时阻断恶意进程。</span></span></font></span><span style="font-family: 宋体;font-size: 10.5pt;"><o:p></o:p></span></p><p style="margin-bottom: 0px;"><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">深度渗透测试：</span></span></font></span><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">利用</span></span></font></span><span style="font-family: 宋体;font-size: 10.5pt;"><font face="宋体"><span leaf=""><span textstyle="" style="font-size: 15px;">安全审计与合规验证，模拟攻击路径，验证云服务修复方案（如X-CSRF-Token头有效性）是否全覆盖；审计云服务共享文件系统，确保敏感数据隔离。</span></span></font></span></p><section><span style="color: rgba(0, 0, 0, 0.9);font-family: 宋体;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 700;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">如需进一步定制化方案，欢迎联系江苏国骏技术团队，联系电话：400-6776-989/13338963885</span></span></section></td></tr></tbody></table>  
来源：cybersecuritynews  
  
  
  
  
  
  
  
  
