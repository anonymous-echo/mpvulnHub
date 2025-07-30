#  AI安全警报！英伟达喊你修复漏洞了   
原创 智安全  深信服科技   2024-05-31 18:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EJiaEo3Lq9kqDWCMLbVc9HpFnlibGLn4KX0sU7wNvH2lU2r7ufOY4ib8V35o6EUFBxpHQ9iarj2sWKuv5nlAKhGibvA/640?wx_fmt=gif&from=appmsg "")  
  
AI的应用越来越广泛，已经渗透到人们工作和生活的方方面面。随之而来的，是AI的安全问题。我每天都在使用的AI助手，可信吗？企业核心业务依赖的AI服务器，安全吗？**AI软件的安全性，已经成为了一个复杂且多面的全球性议题。**  
  
  
近日，NVIDIA（英伟达） 官方发布了一则安全风险预警和软件更新公告，**公布 NVIDIA Triton 推理服务器存在着重要安全漏洞，提醒用户尽快进行版本更新。**（涉及的漏洞为深信服发现并提报）  
  
  
**Triton 推理服务器是NVIDIA发布的一款开源软件**，作为 NVIDIA AI 平台的重要组成部分，该服务器可以针对各种工作负载，实现标准化的AI模型部署和执行，为用户提供快速且可扩展的AI服务。Triton作为目前**全球主流AI推理服务器**，已被全球众多人工智能厂商广泛使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kqpCjqxLOIC1h8rNfn0ZmAQZzyouib0VRq9qnunCE0XvXvTPR0NVRGm1l1ZDwnJiczsK7EQTqqnhksg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kqpCjqxLOIC1h8rNfn0ZmAQic0EkF7licLKfFVyXxdbK7ibwUytGLDKkNLlcia1ngDH0Uuo3WaZzm0kWA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kqpCjqxLOIC1h8rNfn0ZmAQEezeZ6T2nn46zPHJUXjrN6LBcSicJTvGsLn7Piczl8196NicC8gC1kJuQ/640?wx_fmt=png&from=appmsg "")  
  
**NVIDIA AI平台大多数应用与功能的实现，背后都是由Triton 推理服务器提供基础支持，这代表什么呢？**  
  
对于使用该服务器的厂商、企业来说，**这个漏洞一旦被恶意攻击者利用，****他们的云端AI模型就很有可能完全被控制。**攻击者可以在未授权的情况下实现窃取用户敏感数据、执行恶意代码、修改AI模型计算结果、窃取AI模型等一系列操作，对用户的数据隐私带来的风险是灾难性的，对企业利益和品牌信誉带来的损失也是毁灭性的。  
  
  
假设，某自动驾驶汽车厂商使用Triton 推理服务器来训练和优化自动驾驶模型。这个漏洞被恶意攻击者利用并成功控制，则可能导致车辆误判、失控等安全问题，威胁到乘客和行人的生命安全。  
  
  
再假设，某人工智能服务厂商使用Triton 推理服务器部署和开发其AI模型，如果被攻击者利用此漏洞入侵，可能导致模型计算结果被篡改，甚至直接被“一键复制”式窃取，导致知识产权泄漏或声誉受损。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kqpCjqxLOIC1h8rNfn0ZmAQv5TicvwD5UmV2NKDC3CydqknSFrYOktZhKGFH3usqIS7xJCznHGaic9A/640?wx_fmt=png&from=appmsg "")  
  
  
**对于我们每个人来说就是，你的“AI助手”带着你所有的隐私和数据，背叛你了。**  
  
  
假设，你一直使用的某个对话类AI助手被黑客利用此漏洞控制，你的所有对话内容、日常行为习惯和隐私信息都会暴露，黑客可以公开并售卖你的个人信息，甚至利用这些信息实施诈骗、窃取财产，甚至盗用身份信息进行其他非法行为。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kqpCjqxLOIC1h8rNfn0ZmAQiaf8VEyBZEsctWfU7k8hDeXLb7H3BUDv8gdhia6TWWAGedxuD813dZJw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**深信服安全研究员Lawliet和彭峙酿**在日常研究过程中发现了这两个漏洞，随即编写详细的漏洞报告，积极与监管机构和NVIDIA官方取得联系。NVIDIA官方验证漏洞信息后第一时间发布官方公告提醒用户更新，并致谢深信服。  
  
  
AI技术的发展正如火如荼，但是对AI基础设施安全性的研究才刚刚起步，在可预见的未来会有更多挑战。比如本次发现的漏洞，属于未授权远程代码执行漏洞，影响范围大，未修复可能导致严重后果。面对这些挑战，  
具备主动识别潜在风险的能力，并提前采取行动进行有效的修复和预防，可以为用户使用的安全性提供多一层保障。  
  
  
**再次提醒各位NVIDIA AI推理服务器用户，****请及时检查自己使用的版本是否更新升级，避免引发安全风险！**另外，无论是使用AI推理服务器的厂商还是使用AI服务的个人用户，都应提升安全意识，关注数据安全和隐私保护，在享受AI带来的高效和便利的同时，确保AI使用过程的安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kqpCjqxLOIC1h8rNfn0ZmAQ7adZSSeM5E1nHXCia3aBP8FmSfzSFyJbKr7eyTeDyicgYsErHJXFDIlQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
深信服注重网络安全攻防技术研究，利用攻击方视角解决网络安全问题，并将安全研究技术应用到产品实践中。  
基于多年的技术积累，深信服在国内率先推出了多个前沿安全产品及服务，并在去年首秀自研的安全大模型——安全GPT的技术应用。发布至今，安全GPT已收获130+体验用户。深信服AICP算力平台在2024数字中国创新大赛的“信创赛道”和“城市赛道”中获得2大奖项。  
  
  
近期，彭峙酿等研究员受邀参加国际知名信息安全会议HITB x PHDays 2024，在主论坛发表主题演讲，与全球网络安全专家、团队共同探讨前沿安全技术。  
  
  
未来，深信服将不断提高专业技术造诣，加大对安全研究人才和技术研究层面的投入， 也将持续在AI安全领域深耕，为所有用户的网络安全保驾护航，让AI技术更好地为人类社会的发展做出贡献。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EJiaEo3Lq9krfs3ibEGaKtAM7TnyRPib93bTqsm5kv7utUdcYu8iaHL3HBdE1A8bbh7tVz6WAyog6tTDuSbB9RlkJw/640?wx_fmt=gif "")  
  
  
