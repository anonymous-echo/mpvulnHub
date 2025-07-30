#  【安全圈】网络安全事件周报：勒索组织与国家级黑客同时盯上SAP漏洞   
 安全圈   2025-05-16 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliayKhlPFNUbibCF4s1UHbmEETqd1X9oo9RRGXdV1jrswcZZ0gXn8TcFUszYAvMsZtUPslTfsvSah3A/640?wx_fmt=png&from=appmsg "")  
  
本周全球网络安全态势依旧紧张，多个关键漏洞正被黑客组织大规模利用。其中，SAP NetWeaver系统的重大漏洞（CVE-2025-31324）不仅吸引了RansomEXX、BianLian等知名勒索软件团伙，还被与中国有关的黑客组织Chaya_004持续攻击。该漏洞允许攻击者未经认证上传恶意文件并执行任意代码，已导致数百台企业服务器沦陷。虽然SAP已发布紧急补丁，但许多传统行业用户因系统兼容性问题仍未完成更新，导致风险持续蔓延。  
  
与此同时，Ivanti的终端管理平台又被曝出两个零日漏洞（CVE-2025-4427、CVE-2025-4428），攻击者可组合利用它们绕过身份验证并完全控制设备。Ivanti称问题源于第三方开源组件，但安全专家警告，随着漏洞细节公开，攻击范围可能迅速扩大。这是该公司两年内第七次因供应链安全问题遭遇重大漏洞，暴露企业级设备厂商在依赖管理上的严重缺陷。  
  
**国家级黑客活动不断升级**  
朝鲜APT37（又称ScarCruft）近期加强了对韩国目标的钓鱼攻击，假冒"国家安全会议邀请函"或"朝俄军事合作情报"等内容诱骗受害者下载恶意LNK文件。攻击通过Dropbox等云存储分发RoKRAT木马，成功入侵后能窃取敏感信息并远程控制设备。几乎同一时间，俄罗斯APT28（Fancy Bear）则对东欧军事相关企业的邮件服务器发起"RoundPress"行动，利用RoundCube、Horde等软件的已知漏洞窃取账户凭据，目标包括保加利亚、罗马尼亚等国的军工企业，这些公司为乌克兰提供苏联遗留武器的零部件供应。  
  
**企业安全事件与修复动态**  
北美最大钢铁生产商Nucor近期因网络攻击一度暂停部分工厂运营，目前仍在恢复中，但具体影响范围尚未披露。微软则在5月补丁日中修复72个安全漏洞，其中5个已被黑客利用，包括Windows DWM核心库的权限提升漏洞，攻击者可借此获得系统级控制权。企业应优先部署这些更新，尤其是涉及远程代码执行的高危漏洞补丁。  
  
**行业观察与应对建议**  
近期攻击趋势显示，传统制造业、政府机构及关键基础设施成为黑客的新重点目标，且攻击手法更加依赖社会工程和供应链弱点。安全团队除了加强补丁管理外，还应监测异常认证活动，尤其是云存储平台的可疑文件访问行为。同时，企业需重新评估第三方组件的安全风险，避免因依赖漏洞引发连锁安全事件。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】Interlock勒索软件因间谍驱动的数据泄露而袭击美国国防承包商AMTEC](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=1&sn=7da38b2af3f6c3d9d008e6e7dbf6a691&scene=21#wechat_redirect)  
  
  
  
[【安全圈】PyPI恶意软件警报:恶意的“索拉纳令牌”包瞄准索拉纳开发人员](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=2&sn=938d25c710b282a91672b5b04220c9f5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】*Telegram成犯罪温床："新币担保"黑市涉案84亿美元，牵涉杀猪盘与朝鲜洗钱](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=3&sn=54144bc4949719692769276efdef9cf1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】OpenPubkey和OPKssh中的关键身份验证绕过使系统面临远程访问风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=4&sn=d8cc7ac650197265d67dcbf81f43b31c&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
