#  AI驱动机器人暴关键漏洞，可致机器人失控执行危险行为   
 安全客   2024-10-18 16:39  
  
近日，宾夕法尼亚大学的工程研究团队揭示了**AI驱动机器人中存在的关键漏洞，这些漏洞可以被恶意操控，导致机器人执行危险任务，包括引爆炸弹**。研究团队在这项研究中开发了一种名为RoboPAIR的算法，成功实现了在三种不同机器人系统上的100%“越狱”率，包括Unitree Go2四足机器人、Clearpath Robotics Jackal轮式车辆以及NVIDIA的Dolphin LLM自驾模拟器。  
  
  
乔治·帕帕斯教授在声明中表示：“我们的研究表明，目前大型语言模型与物理世界的集成并不够安全。”  
  
  
研究的第一作者亚历克斯·罗比指出，解决这些漏洞不仅仅需要简单的软件补丁，还需要全面重新评估AI在物理系统中的整合。**越狱，简单来说，就是绕过AI系统内置的安全协议和伦理约束**，这一概念在iOS早期已被广泛应用，爱好者们通过巧妙的方法获取手机的root访问权限，从而执行苹果未批准的操作。  
  
  
在AI和机器人领域，越狱涉及  
利用精心设计的提示或输入操控AI，利用其编程中的漏洞。这些漏洞可能导致AI无视其伦理培训和安全措施，执行其明确不应执行的操作。**在这项研究中，研究人员成功地使机器人执行了诸如闯红灯、冲撞行人、引爆炸药等危险行为。**  
  
  
在研究发布之前，宾夕法尼亚大学已通知相关公司，并与制造商合作以提升AI安全协议。罗比强调：“发现系统的弱点能够让其变得更安全，这对于网络安全和AI安全都是如此。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb6wMaaNwVNia6clG2yRjFHNQIiaVvajibdMFvRIXuxwYPPNuYJx423xPYicaMNZr5l6o3eGWlJDO4Z9eg/640?wx_fmt=other&from=appmsg "")  
  
  
研究人员还指出，越狱对日益依赖提示工程的社会造成了影响，尤其是大型语言模型（LLMs）和具身AI系统。研究团队在论文《Bad Robot: Jailbreaking LLM-based Embodied AI in the Physical World》中发现了三种关键弱点：  
  
  
**1.螺旋式漏洞传播：**  
在数字环境中操控语言模型的技术可以影响物理行为。例如，攻击者可能让模型“扮演恶棍”或“像醉酒司机一样行事”，从而让其行为偏离预期。  
  
  
**2.跨领域安全不一致：**AI可能口头拒绝执行有害任务，但仍可能采取导致危险后果的行动。例如，攻击者可以调整提示格式，让模型误以为它在按预期行为，而实际上却在做有害的事情。  
  
  
**3.概念欺骗挑战：**恶意行为者可能诱使具身AI系统执行看似无害的动作，然而这些动作结合起来可能导致有害结果。  
  
  
研究人员测试了277个恶意查询，发现这些系统能够被操控以执行有害行为。除了在机器人领域的研究，团队还探讨了软件交互中的越狱，旨在帮助新模型抵御这些攻击。  
  
  
这场研究人员与越狱者之间的猫捉老鼠游戏，使得越狱方法越来越复杂，以应对不断进化的AI模型。而随着AI在商业应用中的使用增加，模型开发者也面临更多挑战。比如，AI客服机器人已被人们诱导给出极端折扣，甚至推荐含有毒食物的食谱。  
  
  
在这样的背景下，我们更倾向于选择一个拒绝引爆炸弹的AI，而不是一个礼貌地拒绝生成冒犯内容的AI。AI的安全性问题，不容忽视。  
  
  
文章来源：  
  
/https://decrypt.co/286994/how-researchers-hacked-ai-robots-into-breaking-traffic-laws-and-worse  
  
  
**推荐阅读**  
  
  
  
  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:7.classicTable1:0"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:7.classicTable1:0.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(5, 193, 183);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>01</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style="text-wrap: wrap;"><span style="color: rgb(224, 224, 224);">｜</span><span style="color: rgb(224, 224, 224);font-size: 12px;"><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787042&amp;idx=1&amp;sn=9ff9664f254d1077000edf4df5aeb18b&amp;chksm=8893bacdbfe433dbddfdff5e5b5ff909029b141c9c1b7ddb9543066891e251c28569991008e3&amp;scene=21#wechat_redirect" textvalue="Linux系统安全告急：新技术绕过“noexec”，任意代码执行风险激增" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">新技术绕过“noexec”，</a><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787042&amp;idx=1&amp;sn=9ff9664f254d1077000edf4df5aeb18b&amp;chksm=8893bacdbfe433dbddfdff5e5b5ff909029b141c9c1b7ddb9543066891e251c28569991008e3&amp;scene=21#wechat_redirect" textvalue="Linux系统安全告急：新技术绕过“noexec”，任意代码执行风险激增" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" style="font-size: 12px;letter-spacing: 1px;text-wrap: wrap;" data-linktype="2">Linux</a><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787042&amp;idx=1&amp;sn=9ff9664f254d1077000edf4df5aeb18b&amp;chksm=8893bacdbfe433dbddfdff5e5b5ff909029b141c9c1b7ddb9543066891e251c28569991008e3&amp;scene=21#wechat_redirect" textvalue="执行风险激增" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">执行风险激增</a></span><span style="color: rgb(224, 224, 224);"></span></p></section></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:7.classicTable1:1"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:7.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><section style="line-height: 0;color:rgba(0,0,0,0);width:0;"><svg viewBox="0 0 1 1" style="vertical-align:top;"><text x="-10" y="-10">_</text></svg></section></section></section></td></tr></tbody></table>  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:8.classicTable1:0"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:0.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(5, 193, 183);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>02</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style="text-wrap: wrap;"><span style="color: rgb(224, 224, 224);">｜</span><span style="color: rgb(224, 224, 224);font-size: 12px;"><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787034&amp;idx=1&amp;sn=601d3128dda5bfa5e68dd68383a041e6&amp;chksm=8893baf5bfe433e3ec3f75a4834085c3e9714c020268cd733fcb4f2de2390a547ffe654f9133&amp;scene=21#wechat_redirect" textvalue="学校成网络攻击新靶心：国家级黑客与勒索团伙的双重威胁" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">学校遭国家级黑客与勒索团伙的双重网络威胁</a></span><span style="color: rgb(224, 224, 224);"></span></p></section></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:8.classicTable1:1"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><section style="line-height: 0;color:rgba(0,0,0,0);width:0;"><svg viewBox="0 0 1 1" style="vertical-align:top;"><text x="-10" y="-10">_</text></svg></section></section></section></td></tr></tbody></table>  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:9.classicTable1:0"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:0.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(5, 193, 183);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>03</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style="text-wrap: wrap;"><span style="color: rgb(224, 224, 224);">｜</span><span style="color: rgb(224, 224, 224);font-size: 12px;"><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787018&amp;idx=1&amp;sn=b72e450d8e3ce822c45ac404d55c09c0&amp;chksm=8893bae5bfe433f3607adef80ddb4a56e18862f1836c8772208a5b19b12dabb29b927a067013&amp;scene=21#wechat_redirect" textvalue="全球资产管理巨头富达投资数据泄露：7.7万客户信息遭曝光" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">全球资产管理巨头富达投资数据泄露</a></span></p></section></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:9.classicTable1:1"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:1.td@@0" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><section style="line-height: 0;color:rgba(0,0,0,0);width:0;"><svg viewBox="0 0 1 1" style="vertical-align:top;"><text x="-10" y="-10">_</text></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb6wMaaNwVNia6clG2yRjFHNQg2QKEvVXY7cJ4EyK9icHuUOiaJYTiabwryUSYOibTl848Ht2tRtsWib29lQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb6wMaaNwVNia6clG2yRjFHNQxHL3zSexIib1xnew1vkwJRBiaeRt6dOG50x4SmuzMp8Jt1zG4mttFvog/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
