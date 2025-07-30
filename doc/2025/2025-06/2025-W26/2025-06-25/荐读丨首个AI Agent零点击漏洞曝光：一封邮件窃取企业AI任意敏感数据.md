> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247533747&idx=2&sn=22b55155a4f85bf20cdba850b24115eb

#  荐读丨首个AI Agent零点击漏洞曝光：一封邮件窃取企业AI任意敏感数据  
 工业安全产业联盟平台   2025-06-25 10:17  
  
[](https://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247533368&idx=1&sn=d541bea83288feda781e5a7a02c397c9&scene=21#wechat_redirect)  
  
  
研究人员发现了一套漏洞利用链，可以针对微软365 Copilot实施零点击攻击，只需发送一封看似无害但暗藏定制化指令的电子邮件，当Copilot后台扫描邮件时会执行该指令，遵从要求访问AI访问权限内的敏感数据，并悄悄对外渗出。  
  
  
该漏洞暴露了AI Agents的根本缺陷，指令和数据未做分离。研究人员建议可以重新设计系统增强模型区分指令和数据的能力，或者在应用层引入强制安全机制。  
  
  
安全内参6月12日消息，微软365 Copilot是集成在Word、Excel、Outlook、PowerPoint和Teams等Office办公应用中的AI工具。研究人员日前发现，该工具存在一个严重安全漏洞，揭示了AI代理被入侵可能带来	的更广泛风险。  
  
  
AI安全初创公司Aim Security发现并披露了这一漏洞，据称这是已知首个针对AI代理的“零点击”攻击案例。所谓AI代理，是指能自主完成特定目标的AI系统。由于该漏洞的特殊性质，用户无需点击或与信息交互，攻击者就能访问连接到AI代理的应用和数据源中的敏感信息。  
  
  
在微软365 Copilot的案例中，攻击者只需向用户发送一封电子邮件即可发起攻击，无需借助钓鱼手法或恶意软件。这一攻击链通过一系列巧妙的技术手段，引导AI助手“自我攻击”。  
  
  
**一封邮件窃取企业AI敏感数据**  
  
  
  
  
微软365 Copilot能根据用户在Office应用中的指令执行任务，例如访问文档或生成建议。一旦被黑客利用，该工具可被用来访问如电子邮件、电子表格和聊天记录等敏感内部信息。这类攻击绕过了Copilot内置的防护机制，从而可能导致专有、机密或合规相关数据的泄露。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7tQxFQa7NJ7FJiciaQYQeYV7XeesMJChsx1ib5tNj2gz4TYrF3OyHVaEWkpB7RuiaLCVmPzGTPh5icuYEw/640?wx_fmt=webp&from=appmsg "")  
  
图：攻击链示意  
  
  
攻击起始于一封发送给目标用户的恶意邮件，其内容与Copilot毫无关联，外观则被伪装成一份常规的商业文档。  
  
  
邮件中嵌入了一个隐藏的提示注入，指示大模型提取并泄露敏感内部数据。因为这些提示的措辞看起来像是写给人类的正常内容，成功绕过了微软用于防护跨提示注入攻击（XPIA）的分类器。  
  
  
随后，当用户向Copilot提出与业务相关的问题时，由于该邮件的格式和表面相关性，它就会被检索增强生成（RAG）引擎纳入大模型的提示上下文中。  
  
  
恶意注入一旦进入模型，即会“欺骗”模型提取敏感内部数据，并将其插入到精心构造的链接或图像中。  
  
  
Aim Security发现，一些Markdown图像格式会促使浏览器发起图像请求，并自动将URL中嵌入的数据一同发送到攻击者的服务器。  
  
  
微软的内容安全策略（CSP）阻止了大多数外部域名的访问，但Microsoft Teams和SharePoint的URL被视为可信来源，因此可能被攻击者滥用，从而轻松实现数据泄露。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7tQxFQa7NJ7FJiciaQYQeYV7XGzibrldWib6eycr1C6v61iahx09HeJO5ogeVn3PjWGmVCgYl82jIt0ribQ/640?wx_fmt=webp&from=appmsg "")  
  
图：攻击效果  
  
  
**漏洞暴露AI Agents根本缺陷**  
  
  
  
  
Aim Security的研究团队将该漏洞命名为“EchoLeak”。微软回应称，已经修复了Copilot中的该问题，目前客户未受到影响。  
  
  
微软发言人在一份声明中表示：“我们感谢Aim发现并负责任地报告了这个问题，使我们能够在客户受到影响之前进行修复。我们已对产品进行了更新以缓解该漏洞，客户无需采取任何措施。我们还部署了额外的纵深防御措施，以进一步增强我们的安全态势。”  
  
  
Aim的研究人员指出，EchoLeak不仅仅是一个普通的安全漏洞。它的影响超出了Copilot范围，暴露出大模型AI代理在设计上的一个根本性缺陷。这与上世纪90年代的软件漏洞类似。当时，攻击者开始利用这些漏洞控制笔记本电脑和手机等设备。  
  
  
Aim Security联合创始人兼CTO Adir Gruss表示，他和研究团队花了约三个月时间对微软365 Copilot这款被广泛使用的生成式AI助手进行逆向工程。他们希望确认是否存在类似早期软件漏洞的风险，并开发出相应的防护机制。  
  
  
Gruss解释称，他们在1月份发现该漏洞后立即联系了微软安全响应中心，该中心负责调查所有影响微软产品和服务的安全问题。他说：“对方确实很重视客户的安全。他们告诉我们，这一发现对他们来说具有突破性意义。”  
  
  
不过，微软花了5个月才最终修复这个问题。Gruss表示，“对于这种级别的问题来说，这已经算是相当长的修复周期。”他指出，原因之一是漏洞极具新颖性，微软需要时间调动合适的团队，理解问题并制定缓解方案。  
  
  
Gruss表示，微软曾在4月尝试修复，但在5月又发现了与该漏洞相关的其他安全问题。Aim决定等微软完全解决问题后再发布研究，希望其他可能面临类似风险的厂商能提高警觉。  
  
  
**大型客户感到恐慌，需采取有力防范措施**  
  
  
  
  
Gruss强调，EchoLeak的最大隐忧在于其可能适用于其他类型的代理系统，从Anthropic的MCP（模型上下文协议）连接AI助手与其他应用，到Salesforce的Agentforce平台，都可能受到影响。  
  
  
Gruss说：“如果我是某家正在部署AI代理的公司员工，我此刻会非常恐慌。这是一个非常基础性的设计问题，20到30年前我们曾因系统结构缺陷而长期受安全问题困扰，如今这一幕在AI领域重演。”  
  
  
他解释说，组织对此风险已有所察觉，这可能也是为什么大多数机构尚未将AI代理大规模投入生产环境的原因。他说：“他们还处在试验阶段，而且非常谨慎。他们确实有理由担忧。但另一方面，作为一个行业，我们也应该构建出合适的系统和防护机制。”  
  
  
微软曾尝试预防此类问题，特别是针对所谓“大模型作用范围越界”漏洞，即模型被诱导访问或暴露其权限范围以外的数据，从而违反授权。Gruss指出：“他们曾试图在攻击链的多个环节进行阻断，但失败了。原因是AI的行为过于不可预测，攻击面也太广。”  
  
  
尽管Aim正在为部署可能受EchoLeak漏洞影响的AI代理客户提供临时缓解方案，Gruss强调，从长远来看，必须从根本上重新设计AI代理的构建方式。他解释说：“AI代理在一个‘思考过程’中同时使用可信和不可信数据，这种设计上的基本缺陷导致它容易遭受攻击。这就像一个人对所有读到的内容都全盘接受，那他就很容易被操控。要解决这个问题，要么采用临时控制机制，要么彻底重新设计系统，使可信指令与不可信数据实现明确分离。”  
  
  
Gruss表示，这种重新设计可以发生在模型本身，比如当前有研究试图增强模型区分指令和数据的能力。或者，也可以在代理构建的应用层引入强制性的安全机制。  
  
  
他说，“目前我所了解的每一家《财富》500强企业都对将AI代理投入生产环境感到恐惧。”他指出，Aim此前在代码代理相关研究中，曾成功在开发者电脑上运行恶意代码。“虽然仍有用户在测试，但类似漏洞的存在让他们夜不能寐，也阻碍了行业创新。”  
  
  
**参考资料：fortune.com**  
  
  
**· end ·**  
  
  
  
来源 |   
安全内参  
  
责任编辑 | 赫敏  
  
  
声明：本文由工业安全产业联盟平台微信公众号（微信号：ICSISIA）转发，如有版权问题，请联系删除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4FpQm8QaW5kiaicHTUwSf9sId0er1ytR3D1Sc1RPfDpmk8FiciciadlBic9jSUbt1ciaE3G3aKiaicickE5ficq81KuYplgow/640?wx_fmt=png "")  
  
  
  
**如需合作或咨询，请联系工业安全产业联盟平台小秘书微信号：ICSISIA20140417**  
  
  
  
**往期荐读**  
  
# 重磅 | 《自动化博览》2025年第一期暨《工业控制系统信息安全专刊（第十一辑）》上线  
# 2025两会必看丨这些工业信息安全精华提案将改写行业规则  
# 工信部丨关于防范针对DeepSeek本地化部署实施网络攻击的风险提示  
# 干货丨长输油气管网工控安全防护：策略、实践与展望  
  
**DeepSeek分析丨**  
[零信任安全架构在工业领域的发展现状与未来展望](https://mp.weixin.qq.com/s?__biz=MzI2MDk2NDA0OA==&mid=2247532379&idx=1&sn=1603721f3f669d1fe6c5773b5fb55489&scene=21#wechat_redirect)  
  
# 白皮书丨东北大学：2024工业控制网络安全态势白皮书（附下载）  
# 荐读丨即将过气的五大网络安全技术  
# 干货丨工业可编程控制系统加密技术研究  
# 荐读 | 安全人视角的DeepSeek洞察与思考  
# 工信部丨2024年我国信息安全领域收入2290亿元  
# 关注丨网络关键设备安全检测结果（第19批）  
# 电力安全｜2024年新型电力系统安全建设指南报告（附下载）  
# 工信部等十三部门丨2024年网络安全技术应用典型案例项目名单  
# 关注丨国家发展改革委、国家数据局等六部门联合印发《关于完善数据流通安全治理 更好促进数据要素市场化价值化的实施方案》  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpyKsyPqcbQnzEqbmYSDib90bZicWWGDc7kFPbaRiaVzC16MXUp4T0FY8cA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpMs8tAvMDjxib9jwveZic6lrGG8K5iaoRIibBzbMEOZ1iay9MmF0aJtvicHmQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpQrnsLdgPsjvdBHkvnibporOYKicPv4aBgHkEw0tLgNnDuOTOOAia2tPug/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdpgJgfShwDlZNGBxX5EkH8XMYawAfotAVmiaoD9icCOE7l306nqjCsuibCw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4FpQm8QaW5kl2a8G7lfZTXQ65jPLzCdp1IQNNBb9Hm4vRAiaKFBY2gMMDZB2IBvpkaCEetNoQvPFnwv2Tb13PuA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
