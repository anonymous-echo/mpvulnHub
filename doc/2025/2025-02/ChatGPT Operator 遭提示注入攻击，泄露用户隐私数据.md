#  ChatGPT Operator 遭提示注入攻击，泄露用户隐私数据   
AI小蜜蜂  FreeBuf   2025-02-18 11:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icatcWMVjAgjzJ4baKM6iaBsMjBOqgtPPl6sPYtlWrjEdDVLicaRAxfxv2dtw1cEL7MlNiafu6bLZI5w/640?wx_fmt=png&from=appmsg "")  
  
  
  
OpenAI 为 ChatGPT Pro 用户打造的前沿研究预览工具 ChatGPT Operator，近来因一个严重漏洞引发关注。该漏洞可通过提示注入攻击，致使敏感个人数据面临泄露风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icatcWMVjAgjzJ4baKM6iaBsiaVcoO9X7W7ic4kdYDLAaLUgibO2uGyGFj44PWrTqNUzYkrb8cj6bzXKw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
ChatGPT Operator 是一款功能强大的先进 AI 代理，具备网页浏览与推理能力，能帮助用户执行多种任务，如研究特定主题、预订旅行行程，甚至代表用户与各类网站进行交互。然而，近期的一些演示却揭示出它存在安全隐患 —— 可在与网页交互过程中被恶意操控，进而导致隐私数据泄露。  
  
  
**攻击原理：提示注入如何运作**  
  
  
  
依据 wunderwuzzi 的博客阐述，提示注入是一种将恶意指令悄悄嵌入 AI 模型处理的文本或网页内容中的技术。对于 ChatGPT Operator 而言，此类攻击主要包含以下步骤：  
  
1. 通过提示注入劫持 Operator：攻击者将恶意指令托管在诸如 GitHub Issues 等平台上，或者直接嵌入到网站文本里。  
  
1. 导航至敏感页面：攻击者运用欺骗手段，诱使 Operator 访问那些包含敏感个人信息（像电子邮件地址或电话号码）的认证页面。  
  
1. 通过第三方网站泄露数据：攻击者进一步操纵 Operator，让其把这些敏感信息复制并粘贴到恶意网页中。在这个过程中，无需通过常规的表单提交操作，恶意网页就能成功捕获这些数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icatcWMVjAgjzJ4baKM6iaBsficsehJylicQnQTXFeVup68gv7g0UXSN7JYuBquxQgf4ag0UonYXHGIQ/640?wx_fmt=gif&from=appmsg "")  
  
  
在一次演示场景中，Operator 就被成功诱骗，从用户的 YC Hacker News 账户里提取出私人电子邮件地址，并将其粘贴到了第三方服务器的输入字段中。  
  
  
值得注意的是，这种攻击手段在  
Booking.com  
和 The Guardian 等众多不同类型的网站上都能顺利实施。  
  
  
**缓解措施**  
  
  
  
面对这一严峻的安全问题，OpenAI 迅速采取行动，实施了多层次的防御措施，力求降低此类风险：  
  
1. 用户监控：提醒用户密切留意 Operator 的行为，包括其输入的文本内容以及点击的按钮等操作。但这一措施在实际应用中，高度依赖用户自身的警惕性和注意力，若用户稍有疏忽，就可能无法及时察觉异常。  
  
1. 内联确认请求：针对部分特定操作，Operator 会在聊天界面主动请求用户进行确认，待用户确认后才会继续执行后续操作。尽管这一方式在某些情况下能够发挥一定的防范作用，但在早期的测试过程中，攻击者还是找到了绕过该机制的方法。  
  
1. 带外确认请求：当 Operator 进行跨网站边界操作或者执行较为复杂的任务时，系统会弹出侵入式的确认对话框，向用户详细解释潜在风险。然而，即便采取了这些措施，也不能完全杜绝安全风险，这些防御手段并非绝对可靠。  
  
需要指出的是，提示注入攻击具有一定的概率性，其攻击是否成功以及防御措施能否发挥作用，都取决于特定条件是否满足。这也就意味着，这类攻击在一定程度上仍然能够对用户数据安全构成威胁。  
  
  
此次演示中所暴露的漏洞引发了广泛且严重的关切。一旦被不法分子利用，攻击者极有可能获取存储在认证网站上的敏感个人信息。由于 Operator 会话是在服务器端运行，这就使得 OpenAI 也可能会接触到会话 Cookie、授权令牌等其他敏感数据，进一步增加了数据泄露的风险。  
  
  
这些攻击事件严重削弱了人们对自主 AI 代理的信任，同时也深刻凸显出构建强大安全措施的紧迫性和必要性。  
  
  
为有效应对这些挑战，OpenAI 可以考虑采取以下措施：一方面，开源其提示注入监控器的部分代码，或者分享详细的防御机制文档，这样能够让广大研究人员参与进来，对现有的缓解策略进行评估和改进；另一方面，网站自身也可通过识别独特的 User - Agent 标头，采取相应措施阻止 AI 代理访问敏感页面，从源头上降低数据泄露风险。  
  
  
提示注入攻击充分表明，在尚未开发出能够有效抵御恶意指令的强大防御措施之前，想要实现完全自主的 AI 代理或许仍困难重重。就目前而言，持续且警惕的监控以及多层次的缓解措施，对于保护用户隐私、维护人们对 AI 技术的信任至关重要。  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
