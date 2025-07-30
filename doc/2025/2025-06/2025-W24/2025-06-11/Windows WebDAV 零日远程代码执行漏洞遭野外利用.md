#  Windows WebDAV 零日远程代码执行漏洞遭野外利用  
 信息安全大事件   2025-06-11 10:01  
  
微软已确认其Web分布式创作和版本控制（WebDAV）实现中存在一个严重的零日漏洞正遭攻击者野外利用，这促使微软在2025年6月的补丁星期二发布紧急安全更新。  
  
该漏洞编号为CVE-2025-33053，属于严重的远程代码执行（RCE）缺陷，允许未经授权的攻击者通过外部控制WebDAV中的文件名或路径，通过网络执行任意代码。此安全漏洞影响所有受支持的微软Windows版本，使其成为当前补丁周期中修复范围最广的漏洞之一。  
  
微软在安全公告中表示："WebDAV中文件名或路径的外部控制允许未经授权的攻击者通过网络执行代码。"该漏洞被评定为"重要"严重等级，成功利用需要用户交互。  
  
野外活跃利用现状  
  
Check Point Research的安全研究人员发现该漏洞并报告了野外活跃利用的证据。攻击媒介要求受害者点击特制的WebDAV URL，从而触发远程代码执行漏洞。  
  
微软在解释利用方法时表示："用户需要点击特制的URL才会被攻击者入侵。"尽管需要用户交互，但由于该漏洞可能导致整个系统沦陷，仍构成重大风险。  
  
该漏洞影响广泛的微软系统，微软已为Windows 10、Windows 11和各种Windows Server版本分发补丁。  
  
微软2025年6月的补丁星期二共修复了66个漏洞，CVE-2025-33053是本次修复的两个零日漏洞之一。  
  
WebDAV组件通过与Microsoft Edge中的Internet Explorer模式以及其他应用程序中的WebBrowser控件集成，显著扩大了攻击面。  
  
微软指出，虽然Internet Explorer 11在某些平台上已停用，但底层的MSHTML平台仍受支持且存在漏洞。  
  
鉴于已确认野外利用，安全专家强烈建议立即部署可用补丁。  
  
该漏洞延续了近年来威胁行为体日益针对WebDAV相关安全问题的趋势。  
  
使用旧版Windows系统和启用Internet Explorer兼容模式的机构面临更高风险。  
  
微软建议安装仅安全更新的客户同时安装相应的IE累积更新，以确保完全防范此漏洞。  
  
<table><tbody><tr><td data-colwidth="576" style="border-color:#ffd7d5;background-color:#fff2f2;"><p style="text-indent: 0px;margin-top: 8px;margin-bottom: 8px;line-height: 2em;" data-pm-slice="3 3 []"><span leaf="" style="font-size: 10.5pt;font-family: 宋体;">针对此次漏洞，江苏国骏可以为客户提供以下服务</span></p><p style="text-indent: 0px;margin-top: 8px;margin-bottom: 8px;line-height: 2em;" data-pm-slice="3 3 []"><span leaf="" style="font-size: 10.5pt;font-family: 宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">漏洞应急响应服务</span><span textstyle="" style="font-size: 17px;">：漏洞影响评估，制定紧急修复方案</span></span></p><section><span leaf="" style="font-size:10.5pt;font-family:宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">安全防护体系建设</span><span textstyle="" style="font-size: 17px;">：边界防护加固，部署下一代防火墙，针对WebDAV协议进行深度检测；配置IPS/IDS规则拦截漏洞利用行为</span></span></section><section><span leaf="" style="font-size:10.5pt;font-family:宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">终端安全防护</span><span textstyle="" style="font-size: 17px;">：部署终端检测与响应(EDR)系统，实时监控可疑行为；实施应用程序白名单机制，阻止恶意代码执行</span></span></section><section><span leaf="" style="font-size:10.5pt;font-family:宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">安全运维服务</span><span textstyle="" style="font-size: 17px;">：持续漏洞管理；建立漏洞扫描机制，定期检查系统漏洞；提供漏洞修复优先级评估和修复方案</span></span></section><section><span leaf="" style="font-size:10.5pt;font-family:宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">安全监控与响应</span><span textstyle="" style="font-size: 17px;">：7×24小时安全监控服务；建立针对此类漏洞的专项检测规则</span></span></section><section><span leaf="" style="font-size:10.5pt;font-family:宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">合规咨询服务</span><span textstyle="" style="font-size: 17px;">：等保合规支持；协助客户满足网络安全等级保护相关要求</span></span></section><section><span leaf="" style="font-size:10.5pt;font-family:宋体;"><span textstyle="" style="font-size: 17px;font-weight: bold;">风险评估服务</span><span textstyle="" style="font-size: 17px;">：开展专项安全风险评估，制定风险处置计划</span></span></section><p><span leaf=""><span textstyle="" style="font-size: 17px;letter-spacing: 0.544px;background-color: rgb(255, 242, 242);color: rgba(0, 0, 0, 0.9);font-weight: 400;font-style: normal;">如需进一步定制化方案，欢迎联系江苏国骏技术团队，联系电话：</span><span textstyle="" style="font-size: 17px;letter-spacing: 0.544px;background-color: rgb(255, 242, 242);color: rgba(0, 0, 0, 0.9);font-weight: bold;font-style: normal;">400-6776-989/13338963885</span></span></p></td></tr></tbody></table>  
  
  
  
**推荐阅读**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/JqliagemfTA6iaLkNkoIyrcTq1jErRmY0MJ1z1xtCujHY8tntYedwef2pfhZUHEXS4N3lrn50zibmkuRDVu9D85dg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**1**  
  
[江苏国骏网络安全服务业务全景 ](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247490721&idx=2&sn=6a12cec92cbb74648773060c6255aa01&scene=21#wechat_redirect)  
  
  
**2**  
  
[【业务介绍】勒索病毒专项防护工作](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247490721&idx=4&sn=c64426bef9775eecf37bfc0f4cbb8a7c&scene=21#wechat_redirect)  
  
  
  
