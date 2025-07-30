> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514631&idx=1&sn=fd5a357122fb4f7943b832c639bc9e1a

#  MCP工具链首个严重漏洞？一个钓鱼网页，远程劫持开发者电脑  
安全内参编译  安全内参   2025-07-03 09:35  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7s2qrQjEausFHsxCWWyDXfDWqY52e5u2icibRjLMTySh3uq6CCTAkdicjbrichxdAoRvKwP8kBDGZibMNA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
研究人员发现，用于测试的MCP Inspector工具存在远程命令执行漏洞CVE-2025-49596，攻击者只需诱导开发者访问暗藏攻击代码的正常网站，即可远程劫持其电脑；  
  
  
数据显示，暴露在互联网上且受该漏洞影响的MCP Inspector实例为数不少，中国也有一定数量的风险实例。  
  
  
前情回顾·  
AI安全威胁态势  
- [实战：滥用MCP服务攻击企业AI，窃取企业内部数据](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514575&idx=1&sn=f10507cd61978c02f006c9d9f30ef3f8&scene=21#wechat_redirect)  
  
  
- [MCP服务泄露客户敏感数据，知名企业紧急下线修补](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514546&idx=1&sn=9e475c8d0292ac7001b0d6491e030db9&scene=21#wechat_redirect)  
  
  
- [首个AI Agent零点击漏洞曝光：一封邮件窃取企业AI任意敏感数据](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514505&idx=1&sn=df286bcbf807c8444c7f8356b70aef56&scene=21#wechat_redirect)  
  
  
- [调查：AI安全明显滞后，仅13%的企业部署了专门防护措施](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514538&idx=1&sn=55d6168988c840b001b050b6c3f85311&scene=21#wechat_redirect)  
  
  
  
  
安全内参7月3日消息，知名大模型公司Anthropic的模型上下文协议（MCP）Inspector工具日前被曝出严重漏洞，在AI开发社区引发震动。  
  
该漏洞暴露了一条关键的攻击路径，黑客只需诱导开发者访问恶意网站，便可在其设备上远程执行任意代码。  
  
  
**CVE-2025-49596构成严重安全威胁**  
  
  
该漏洞被编号为CVE-2025-49596，CVSS评分高达9.4，影响所有0.14.1之前版本的MCP Inspector。  
  
该漏洞由应用安全厂商Oligo Security的研究团队发现，是MCP生态系统首批严重级别的远程代码执行漏洞之一。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7s2qrQjEausFHsxCWWyDXfDN2C2scKzy1MCL4GEiaiaTeJdCVbqF5zEOldGbyuiak93memPHIyQMwb8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
该漏洞的根源在于，Inspector客户端与代理服务器之间缺乏身份验证。攻击者未经身份验证，即可通过该工具的标准输入/输出接口发送的请求，从而触发任意命令的执行。  
  
  
**漏洞的利用方式**  
  
  
MCP Inspector被广泛用于调试和测试MCP服务器，而MCP服务器是支持AI代理在Python与JavaScript等平台之间协作的基础组件。  
  
在默认设置下，MCP Inspector会在0.0.0.0:6277端口上运行一个HTTP服务器，允许通过任何网络接口进行访问。关键问题在于，其默认配置既无身份验证，也未启用加密，为攻击者打开了方便之门。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/FzZb53e8g7s2qrQjEausFHsxCWWyDXfDdwzbkvhcOXyngOfJ1aRnZS4Tb8Rp6gfRrhwLsYL5wYbwRlG8xU8qTg/640?wx_fmt=gif&from=appmsg "")  
  
此次攻击利用了一项长期存在的浏览器漏洞，被称为“0.0.0.0-day”，该漏洞允许网站向本地服务发送请求。  
  
攻击者可构建一个嵌入JavaScript代码的恶意网站，向MCP Inspector的SSE端点发起请求，从而指令其执行系统命令。  
  
这可能导致开发者设备被完全攻陷，风险包括数据被窃取、系统被植入后门，以及在网络中横向移动。  
  
Oligo Security研究员Avi Lumelsky表示：“一旦攻击者能在开发者设备上执行代码，他们便能窃取数据、安装后门，并在网络中横向移动。对AI开发团队、开源项目及依赖MCP的企业用户而言，这构成了重大风险。”  
  
微软、谷歌等主要科技公司以及众多开源项目普遍依赖MCP Inspector进行AI开发。  
  
研究人员还识别出了多个暴露在互联网环境中的MCP Inspector实例，证实该漏洞对个人和组织切实构成亟需解决的远程代码执行风险。  
  
  
**修复措施与建议**  
  
  
Anthropic的安全团队已迅速做出响应，并于2025年6月13日发布了0.14.1版本更新。该版本引入了基于会话令牌的身份验证机制（类似Jupyter笔记本），并加强了来源验证，旨在防止未经授权的请求并减轻跨站请求伪造（CSRF）攻击风险。  
  
Anthropic强烈建议用户立即升级至0.14.1或更高版本，因为旧版本缺乏有效的替代修复方案。  
  
此次事件再次凸显了默认安全配置的重要性，以及开发工具暴露在localhost情况下可能带来的风险。  
  
开发者与组织必须确保其MCP Inspector已更新至安全版本，并避免将其暴露在不受信任的网络环境中。  
  
随着AI生态系统的日益成熟，实施稳健的安全实践对于维护关键开发基础设施的完整性至关重要。  
  
  
**参考资料：gbhackers.com**  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
