#  大量 Four-Faith 路由器因严重漏洞面临远程攻击风险   
河北镌远  河北镌远网络科技有限公司   2025-01-03 10:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5xic9OHsHiafbUVg4naibSQnNsuMVRYqdlLLzHovhH9jcrrEaj6ia94y9TTpBJTlQDQBcgwMczFq8BRURR9fJIdeLg/640?wx_fmt=gif&from=appmsg "")  
  
**点击“蓝字”**  
  
  
一起来关注我们吧  
  
  
  
**近日，网络安全公司VulnCheck揭露了一项针对四信(Four-Faith)工业路由器的高风险漏洞，该漏洞被标识为CVE-2024-12856。**这一操作系统命令注入错误允许远程攻击者在特定条件下执行任意命令，具体来说，只有当攻击者能够成功验证身份时才能触发此漏洞。然而，若路由器使用的是默认凭证且未进行更改，则可能使攻击者绕过身份验证要求，直接执行命令。  
  
据VulnCheck的研究报告指出，在实际发生的攻击案例中，攻击者利用了路由器出厂设置中的默认凭据来激活漏洞，并通过启动反向shell获得了持久性的远程访问权限。值得注意的是，此次攻击活动源自IP地址178.215.238[.]91，而这个IP地址之前已被用于CVE-2019-12168漏洞的攻击行动中，后者同样是一个影响四信路由器的远程代码执行漏洞。根据威胁情报平台GreyNoise的数据记录显示，在2024年12月19日之前，仍有针对CVE-2019-12168的活跃攻击实例存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafa4Z4EXbyaxs4yuEN4KNwI6BZKXA1JqF3xpxUCABEuicqAH3rvHQAjarmjkRqdciaSpnuOIu7DAGbicg/640?wx_fmt=png&from=appmsg "")  
  
  
研究员雅各布·贝恩斯(Jacob Baines)在其发布的分析报告中提到，攻击者至少可以通过HTTP请求对四信F3x24和F3x36型号路由器发起攻击，特别是当提交类型设置为调整系统时间(submit_type=adjust_sys_time)时，adj_time_year参数成为了操作系统命令注入的入口点1。一旦成功利用该漏洞，攻击者便能够在目标路由器上部署恶意软件、窃取敏感信息或干扰网络服务，并可能将受感染的路由器作为进一步攻击其他系统的跳板。  
  
Censys提供的最新统计数据显示，当前有超过15,000台四信路由器直接连接到公共互联网上，这意味着这些设备处于潜在的安全威胁之下。已有迹象表明，自2024年11月初起，就有攻击者开始尝试利用CVE-2024-12856漏洞实施攻击。面对这一情况，VulnCheck已于2024年12月20日正式通知了四信厂商有关漏洞的存在，但截至发稿时为止，官方尚未提供相应的修复补丁。  
  
鉴于路由器在网络架构中的关键作用及其常常被忽视的安全性问题，此类事件再次提醒我们加强网络基础设施防护的重要性。最近几个月里，不仅发现了影响四信路由器的新漏洞，还有如DrayTek Vigor系列在内的多个品牌路由器也被曝出存在包括但不限于缓冲区溢出及命令注入在内的多项安全缺陷。因此，对于企业和个人用户而言，及时更新设备固件、更改默认登录凭据以及采取必要的安全措施显得尤为重要，以确保网络环境的安全稳定运行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafZBZZ3yiaibiaZCPcv4FLUUkic7Juicamh0zLreL6e2KWZpz8iaeeyEnrmV98VmYN5UibkP0tQQoRz5FAswg/640?wx_fmt=png "")  
  
  
  
