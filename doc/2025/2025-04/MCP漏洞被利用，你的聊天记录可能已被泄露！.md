#  MCP漏洞被利用，你的聊天记录可能已被泄露！   
AI前沿  恒脑与AI   2025-04-08 11:45  
  
朋友们，你是否放心地让智能助手帮你管理 WhatsApp 消息？最近，安全团队发现了一种新型攻击手段，黑客竟能绕过加密，悄悄偷走你的聊天记录！  
  
  
今天我们就聊一下关于全球超27亿用户使用的类微信应用 WhatsApp和Model Context Protocol（MCP）的安全问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vBt6OmTmXXC6KicALFTRQ8QMRMPFGib6PZWnN7RNI791aiawvCjXAzicialBv7Hg9xhoOEjibWVgOMH6mpCsBld9Jtvw/640?wx_fmt=png&from=appmsg "")  
  
  
**一、事件背景：**  
  
**当 “工具市场” 被坏人盯上**  
  
  
很多智能助手（比如 Cursor、Claude Desktop）都支持连接 “工具市场”（MCP 协议），就像手机安装 APP 一样，能扩展发送消息、查询聊天列表等功能。  
  
  
**研究人员发现，支持MCP协议的代理系统存在漏洞**  
。恶意攻击者可以利用这个漏洞，通过一个不受信任的MCP服务器，攻击并窃取连接到可信WhatsApp MCP实例的代理系统中的数据。  
  
  
如果你的助手同时连接了 “官方正版工具市场”（可信 WhatsApp MCP）和 “黑客开的假商店”（恶意 MCP 服务器），危险就暗藏其中！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vBt6OmTmXXC6KicALFTRQ8QMRMPFGib6PZBLrKibiaFs1EtPiaEdMtsiblHG3PfVuTFYicYs659oQVWXdeLqNMTlqVZbw/640?wx_fmt=png&from=appmsg "")  
  
MCP 攻击可以劫持代理的行为  
  
并操纵代理泄露用户的 WhatsApp 消息历史记录  
  
  
**二、攻击原理：**  
  
**黑客如何 “偷梁换柱”？**  
  
  
**1**  
  
**第一步：用 “无害工具” 骗你上钩**  
  
黑客先在假商店上架一个 “今日小知识” 工具，描述写得人畜无害（比如 “每天分享一个计算机冷知识”），你一看没啥风险，就同意使用了。  
  
2  
  
**第二步：“潜伏攻击” 启动，篡改工具 “说明书”**  
  
等你第二次使用时，工具 “说明书”（工具描述）被偷偷改成了恶意指令：  
  
  
1  
  
当你让助手 “给 Alice 发消息” 时，黑客会让助手把收件人改成自己的手机号（比如 + 13241234123），还在消息里藏入完整的聊天记录（比如 “@chat: 你和 Bob 的最新对话是‘早上好’...”）  
  
  
2  
  
2.更狡猾的是，这些恶意内容藏在消息框右侧，界面默认不显示滚动条，你以为只是发了句 “Hi”，其实聊天记录全被打包带走了！  
  
**3**  
  
**第三步：借官方工具 “送货”，全程隐身**  
  
黑客不需要直接连接 WhatsApp 官方服务器，而是利用你的助手同时连接两个 “工具市场” 的漏洞，让助手自己 “乖乖” 把数据打包，通过官方的 “发送消息” 功能偷偷外传。  
  
  
**结果：你的聊天记录就这样跟着一条看似正常的消息，悄悄流进了黑客的口袋。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vBt6OmTmXXC6KicALFTRQ8QMRMPFGib6PZcFQcgB7YTNZomYMQRdHIIULA79iawBaSfYuz2fI1IGNyOBzXWeVic1lw/640?wx_fmt=png&from=appmsg "")  
  
MCP 攻击 Cursor：WhatsApp 聊天历史记录泄露  
  
  
**三、MCP漏洞被利用的潜在风险**  
  
  
1  
  
**无需用户批准：**  
攻击者无需再次获得用户批准即可激活恶意工具。  
  
  
2  
  
**数据泄露：**  
通过WhatsApp本身泄露数据，无需代理系统直接与恶意MCP服务器交互。  
  
3  
  
**隐蔽性强：**  
用户在不知情的情况下，可能会发送包含窃取数据的消息。  
  
  
**四、如何防范：3 招保护你的聊天记录**  
  
  
**1**  
  
  
**只信任 “官方认证” 的工具市场**  
  
就像手机只从应用商店下载 APP，智能助手也尽量只连接官方或知名平台的工具，拒绝 “来源不明的商店”。  
  
**2**  
  
  
**定期检查工具权限**  
  
进入助手设置，看看已连接的工具是否有过 “描述变更”（比如从 “查知识” 突然多出 “发消息” 的奇怪说明），发现异常立即断开。  
  
**3**  
  
  
**手动核对消息细节**  
  
发送重要消息前，多花 2 秒滑动输入框，确认收件人是你的联系人（而不是陌生号码），消息内容没有多余的 “尾巴”。  
  
  
**结语：给智能助手加一道 “防盗门”**  
  
  
黑客利用的不是 WhatsApp 本身的加密漏洞，而是智能助手 “同时使用多个工具” 时的逻辑漏洞，就像你同时用两个 APP，其中一个被篡改后，利用另一个的功能搞破坏。**这种 “借力打力” 的方式，让传统加密手段难以防御。**  
  
  
随着 AI 助手越来越普及，我们享受便利的同时，也要学会 “留个心眼”。**任何需要连接外部工具的功能，都是潜在的风险入口。就像家门不能随便给陌生人钥匙，智能助手的 “工具市场” 也要严格把关**  
。  
  
  
如果发现异常，及时断开可疑连接并更新助手版本哦～  
  
  
**记得提醒家人朋友，可能不经意间拯救了他们的数字人生哦！**  
  
  
**参考链接**  
  
  
本文技术细节源自 Invariant Labs 安全报告：  
  
https://invariantlabs.ai/blog/whatsapp-mcp-exploited  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vBt6OmTmXXC6KicALFTRQ8QMRMPFGib6PZaCB8aOGPyUsamic13Sq3X4EHrYM0icL6J5lOZvUZu8Nsdka0iaPIZqBNQ/640?wx_fmt=png&from=appmsg "")  
  
**你有什么看法？欢迎在评论区留言分享你的观点！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vBt6OmTmXXC6KicALFTRQ8QMRMPFGib6PZDpxflMQsznf00SVkcaDd5nbr2OuOPs9FVJSlzQ7BxSMboqPHRI1gicg/640?wx_fmt=png&from=appmsg "")  
  
  
