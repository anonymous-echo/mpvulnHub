#  Adobe最新漏洞被披露，已有PoC代码流出   
工业互联网安全  金瀚信安   2024-12-27 05:27  
  
Adobe近期发布了紧急安全更新，针对ColdFusion中的一个关键漏洞，该漏洞已有概念验证（PoC）代码流出。根据周一的公告，这个编号为CVE-2024-53961的漏洞源于路径遍历弱点，影响了Adobe ColdFusion 2023和2021版本，攻击者可借此读取易受攻击服务器上的任意文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TIag8Q0ibm1jkx3gSC5h7ia7icxiaunchQfMkRJbjYqzGicz9JGRp0oXU5iaa8Aia6OQiazwtxnibqLmkaYCy3MX74RnibuA/640?wx_fmt=jpeg&from=appmsg "Adobe最新漏洞被披露，已有PoC代码流出")  
  
  
Adobe指出，鉴于该漏洞已有可用的PoC代码，可能导致任意文件系统读取，因此将其评为“优先级1”严重等级，警示用户该漏洞面临更高的被攻击风险。  
  
  
Adobe建议管理员尽快安装当天发布的紧急安全补丁（ColdFusion 2021更新18和ColdFusion 2023更新12），最好在72小时内完成，并按照ColdFusion 2023和ColdFusion 2021锁定指南中的安全配置设置进行操作。  
  
  
尽管Adobe尚未透露该漏洞是否已在野外被利用，但建议客户查阅更新的串行过滤文档，了解更多关于阻止不安全Wddx反序列化攻击的信息。  
  
  
今年5月，美国网络安全与基础设施安全局（CISA）曾警告软件公司，在产品发布前应消除路径遍历安全漏洞，因为攻击者可利用这类漏洞访问敏感数据，包括可用于暴力破解现有账户和入侵系统的凭证。  
  
  
去年7月，CISA还要求联邦机构在8月10日前保护其Adobe ColdFusion服务器，防范两个被利用的关键安全漏洞（CVE-2023-29298和CVE-2023-38205），其中一个为零日漏洞。  
  
  
一年前，美国网络安全局还披露，自2023年6月以来，黑客一直利用另一个关键的ColdFusion漏洞（CVE-2023-26360）入侵过时的政府服务器。从2023年3月起，该漏洞在“非常有限的攻击”中被作为零日漏洞积极利用。  
  
  
来源：  
FreeBuf  
  
  
**往期文章回顾：**  
  
[微软被迫实施网络安全整改：因甲方采购审计未过关](https://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492794&idx=2&sn=e153c852df297a3757dba6397d4d4d6c&scene=21#wechat_redirect)  
  
  
[从勒索软件到APT：揭开制造业面临的8大网络安全威胁](https://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492752&idx=1&sn=e0a49d038a64a1b076074081f16e0ab1&scene=21#wechat_redirect)  
  
  
[17家单位联合发布《工业和信息化领域数据安全合规指引》](https://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492720&idx=1&sn=c6ba6e0189e7c4750b48a7095a32b205&scene=21#wechat_redirect)  
  
  
[超2700万美国人面临供水安全威胁](https://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492704&idx=2&sn=2e585673ef6e98c7613d4330e924881f&scene=21#wechat_redirect)  
  
****  
  
[黑客使用 ZIP 文件串联来逃避检测](https://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492687&idx=1&sn=b4da0a42d72e2d0454ecd138984f846b&scene=21#wechat_redirect)  
  
  
[网络安全商业十诫](https://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492669&idx=1&sn=30cc7a3b5e67617ff0a8692f57a5f372&scene=21#wechat_redirect)  
  
  
[Ollama AI框架被曝严重漏洞，可导致DoS、模型盗窃和中毒](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492648&idx=1&sn=7db36541e54953300249db8c67b6fb10&chksm=9789066ea0fe8f78f3e8c36d5bef655031bab0bed502516777a0ef9a8371649f5e9f43e06220&scene=21#wechat_redirect)  
  
  
[福尔摩斯网络安全方法：通过暴露验证，消除“漏洞”](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492612&idx=1&sn=075abaa7617d0630d721c7a053320fd3&chksm=97890642a0fe8f54bc100f4fc8366ccde695a0102836235a0b4836180de5c1db7612ba902ca5&scene=21#wechat_redirect)  
  
  
[伊朗黑客使用ChatGPT策划ICS攻击](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492486&idx=2&sn=fe8b49e43225a071fe119ec37e148823&chksm=978901c0a0fe88d61895cd45e4db30acb3bb974796dc56729699e8a152c8f5e07426bcfa7acb&scene=21#wechat_redirect)  
  
  
[我国工业互联网安全领域首批国家标准发布](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492476&idx=1&sn=1d83182b9b00d25a77a119eda193d5dd&chksm=9789013aa0fe882cc6fce145bc9353e148373180de16a82639ba627d4e6a2e6225ae616e08b2&scene=21#wechat_redirect)  
  
  
[英国一核设施曝出严重网络安全失误，已造成国家安全威胁](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492248&idx=1&sn=8237e720406168970362d00965163d84&chksm=978900dea0fe89c8c9d51df498bb47c17f57d5fa16382169b4742b214e1f090591e58164f9de&scene=21#wechat_redirect)  
  
  
[全球最大白银生产商Fresnillo遭遇网络攻击](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247492201&idx=2&sn=c7c361fa2616b49186007cc9525715fb&chksm=9789002fa0fe8939bc4bb0f3fa9160f5b121e33aa341be33ab8e7894c98d6dc59f1059f460fe&scene=21#wechat_redirect)  
  
  
[原创 | 近年全球石油天然气行业网络安全事件汇总分析](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247491814&idx=2&sn=0830b401ecb6cb332031ec8d2f757502&chksm=978902a0a0fe8bb63a2996e5b2cd69efaf9aabe30bf689923b2a84afbecdc9211e7eaacfd508&scene=21#wechat_redirect)  
  
  
从孤岛到协同：IT-OT融合才是加强工业网络安全的未来  
  
[开启工业领域数据安全保护新阶段，护航新型工业化高质量发展](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247491458&idx=1&sn=93762cf5d344e0ddbe246530998ec720&chksm=978afdc4a0fd74d2ad7887631dc3a1a6a11dcf4566c974db92d076c8a4fea05201784fbba2ae&scene=21#wechat_redirect)  
  
****  
  
[2024年工业控制系统（ICS）和运营技术（OT）威胁与风险预测](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247491441&idx=1&sn=90e54eac0f19fb3abfd2ace40af103c5&chksm=978afd37a0fd74212f3254fdccfe09c95a132ce950b8794b79f5805edcda40c31a4feb676366&scene=21#wechat_redirect)  
  
  
[“梅开二度”！工业自动化巨头施耐德电气遭Cactus勒索软件攻击](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247491325&idx=1&sn=6674b690aaf5f96e0d85fbfab45afa8d&chksm=978afcbba0fd75ad993cbc0654f57c1b758e58d75ad826e9800ae0faeb2c025d0a551a1e837f&scene=21#wechat_redirect)  
  
****  
  
[关键信息基础设施安全保护论坛成功举办](http://mp.weixin.qq.com/s?__biz=MzIxNjI2NjUzNw==&mid=2247491272&idx=2&sn=71128fb1d7530e1eb960295cca6a9462&chksm=978afc8ea0fd75981b5c8035273e73330d099c66608c4f8fb9e54a365cfb438482b35ad65bc0&scene=21#wechat_redirect)  
  
  
勒索软件攻击导致加拿大政府发生大规模数据泄露  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TIag8Q0ibm1h5Ss9HMeQTJed0iakmajmxJs0c4wcJ2CopO4BF1DN8f3iaHIfL1StJI2T9dqn2ScMfboYnMu5S6hiaQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
