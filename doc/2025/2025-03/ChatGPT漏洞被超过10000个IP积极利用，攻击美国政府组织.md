#  ChatGPT漏洞被超过10000个IP积极利用，攻击美国政府组织   
 安全客   2025-03-19 16:24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb4Umu6IA8XdVQOqvsv9KbRicdmWrqVHrx2mJch9DPanblQWyA5CUl0RAPPLKTOe8yvnxOPtfb3lfjw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
近期，网络安全公司 Veriti 发布的研究报告揭示，黑客正在积极利用OpenAI ChatGPT基础设施中的服务器端请求伪造（SSRF）漏洞（CVE-2024-27564）。尽管该漏洞的严重性被归类为中等，但它已经被大规模武器化，成为全球网络攻击的一个新威胁。更值得注意的是，尽管攻击者正在利用这一漏洞进行攻击，但目前没有证据表明OpenAI本身的系统已遭突破。  
  
  
**01**  
  
**漏洞概述与影响**  
  
  
CVE-2024-27564漏洞是一个SSRF漏洞，攻击者可以通过在输入参数中注入恶意URL，诱使ChatGPT系统发起未授权的请求。服务器端请求伪造漏洞通常出现在用户输入数据未经过充分验证时，攻击者可以借此漏洞操控系统发起各种请求，可能绕过现有的安全控制机制。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4Umu6IA8XdVQOqvsv9KbRicyHKaBWP3AUyFL4ZemsW4LiciagiaHKOjwjSBambbcXxqnbSYFOK7ugc3Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
在这一案例中，攻击者主要通过操控ChatGPT的pictureproxy.php组件的url参数，发动攻击，攻击范围可以扩展到其他服务器或同一服务器内部的资源。通过此漏洞，攻击者能够获取原本应受到保护的数据或进行不法操作，造成安全威胁。  
  
  
尽管该漏洞被标为中等严重性，但它已经成为一个活跃的攻击向量，尤其是金融机构和政府组织成为了攻击的主要目标。  
  
  
**02**  
  
**攻击规模与全球分布**  
  
  
Veriti的研究显示，攻击者通过一个恶意IP地址在一周内发动了超过10,000次的攻击尝试。这一庞大的攻击数据表明，黑客并非简单的随机攻击，而是在有组织、有目的地进行大规模的攻击行动。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4Umu6IA8XdVQOqvsv9KbRicDFeyLKbWGCvgeB0TRguXVKn64Miasm7nIBPvkaIg3ROeiciafSF79KoXw/640?wx_fmt=png&from=appmsg "")  
  
  
目前，这种攻击影响已经涉及全球范围，其中美国受到的攻击最为集中，占33%，其次是德国和泰国，各占7%。其他受影响的地区包括印度尼西亚、哥伦比亚和英国。  
  
  
攻击活动在2025年1月骤然增加，随后在2月和3月略有下降，这可能与攻击者的战术调整或安全防护措施的升级有关。这一攻击趋势显示出黑客利用漏洞的方式越来越高效，也提醒我们即便是中等严重性的漏洞，也有可能被恶意利用，造成无法预估的后果。  
  
  
**03**  
  
**攻击目标与漏洞评估**  
  
  
Veriti的研究还发现，由于安全系统（包括入侵防御系统(IPS)、网络应用防火墙(WAF)和传统防火墙）配置不当，相当一部分组织（35%）的防护能力不足。尤其是金融机构，由于其对AI服务和API集成的高度依赖，成为了攻击者的首选目标。  
  
  
金融机构和政府组织的业务系统往往是攻击者的高价值目标，因为一旦成功攻击，不仅可以获取敏感数据，还可能导致大规模的资金损失或信息泄露。  
  
  
具体来讲，攻击带来的潜在后果是严重的。金融机构面临着数据泄露、未经授权的交易、合规处罚以及巨大的声誉损害等风险。对于政府组织来说，信息安全问题同样不容忽视，尤其是在国家安全和敏感数据保护方面，一旦受到攻击，将带来更为严重的后果。  
  
  
研究人员还指出了一个关键点：“没有一个漏洞是小到无关紧要的，攻击者会利用他们能找到的任何弱点”。通常情况下，在安全实践中，关键漏洞和高严重性漏洞往往是优先考虑的对象。然而，Veriti的研究表明，攻击者是机会主义者，他们会利用遇到的任何弱点，无论其严重程度如何。因此，漏洞优先级的确定不应完全依赖于严重性得分，因为攻击趋势可能会迅速转变，曾经被认为无关紧要的漏洞可能会成为最受欢迎的攻击载体，其后果可能是灾难性的。  
  
  
**04**  
  
**安全专家建议**  
  
  
Veriti确定了一份积极参与利用此漏洞的IP地址列表，为安全团队提供了有价值的情报。此外，为了应对这一安全威胁，安全专家建议组织立即实施以下几种缓解策略：  
  
  
  
查看并更正IPS、WAF和防火墙配置，以确保免受CVE-2024-27564的侵害。  
  
  
实施严格的输入验证以防止恶意URL注入。  
  
  
监控日志中是否有来自已知恶意IP地址的攻击企图。  
  
  
考虑网络分段以隔离处理URL获取的组件。  
  
  
在风险评估程序中优先考虑与AI相关的安全漏洞。  
  
  
此次CVE-2024-27564漏洞的利用事件再次提醒我们，在面对现代复杂的网络威胁时，任何看似中等严重的漏洞都可能成为攻击者的突破口。安全防护不应仅仅关注高危漏洞，而应从全局角度审视所有可能的安全隐患。  
  
  
内容来源：  
  
https://cybersecuritynews.com/chatgpt-vulnerability-actively-exploited/   
  
  
**推荐阅读**  
  
  
  
  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>01</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 12px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜<a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788171&amp;idx=1&amp;sn=44e06b5d62d2b5c7d8161ed2dc4ab453&amp;scene=21#wechat_redirect" textvalue="超100家汽车经销商遭供应链攻击，SectopRAT远程访问木马悄然入侵" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">超100家汽车经销商遭供应链攻击</a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>02</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 12px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜<a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788162&amp;idx=1&amp;sn=ead92e907ffe3dc8ae5f3212f1292138&amp;scene=21#wechat_redirect" textvalue="紧急补丁发布：谷歌、苹果、微软联合应对高危零日漏洞 CVE-2025-24201" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2">谷歌、苹果、微软联合应对高危零日漏洞</a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;padding: 0px;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>03</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 12px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜<a target="_blank" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788155&amp;idx=1&amp;sn=7efc6d1ac3416d736815eb5cca191073&amp;scene=21#wechat_redirect" textvalue="浅析新型网络犯罪DeepSeek AI实战应用" linktype="text" imgurl="" imgdata="null" data-itemshowtype="11" tab="innerlink" data-linktype="2">浅析新型网络犯罪DeepSeek AI实战应用</a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4Umu6IA8XdVQOqvsv9KbRicwlr721TF8IMo6jeQbWqTCo2p366iaMuk8nG472NGOzaibb4kYNLCNdsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4Umu6IA8XdVQOqvsv9KbRickHIyjkNDUDzYouMr5WicPx09EVUDRC8b75PGMs3OEJ6SzOOcH5VV8qA/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
