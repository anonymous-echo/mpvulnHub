#  公安机关将公开通缉台黑客；|全球互联网因BGP协议漏洞出现大规模路由震荡；|苹果五年拦截90亿美元欺诈交易；   
 黑白之道   2025-05-29 01:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**公安机关将公开通缉台黑客；**  
  
  
5月28日，国务院台湾事务办公室举行例行新闻发布会发言人陈斌华回答记者提问时表示，近年来，在民进党当局指使下，台湾资通电军频繁对大陆网络开展网攻窃密、“台独”宣传和系统破坏等活动，对大陆网络空间安全等造成干扰，性质极其恶劣。下一步，公安机关将坚决维护国家安全和企业、人民合法正当权益，依法对上述人员公开通缉，并借助各类司法渠道坚决予以打击。  
  
  
  
**全球互联网因BGP协议漏洞出现大规模路由震荡；**  
  
  
2025年5月20日UTC时间7时，一条异常的BGP路由通告在互联网骨干网中传播，触发多个主流BGP实现方案的意外行为，导致全球范围内持续数十分钟的路由不稳定事件。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljL8iaJ5AWpCZUDhDbLLbTdx5ceI0GWurgTqV8BiaBFgUfeP9xHuBJw0NrSkwNDNpG3uziaUT6AAydyw/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
该事件的起因是某些自治系统（AS）在网络中传播了携带错误BGP Prefix-SID属性的路由更新。该属性通常仅用于企业内部网络（遵循RFC8669标准），而非全球互联网路由表。正常而言，现代BGP实现应按照RFC7606标准过滤此类异常属性，但此次事件中，Juniper的JunOS系统并未完全拦截该错误通告，反而将其传播至对等网络。当这些数据包到达运行Arista EOS设备的网络时，由于Arista未启用BGP容错机制，直接导致BGP会话中断，进而引发部分网络短暂失去互联网连接。  
  
根据bgp.tools的数据分析，此次事件波及多个知名网络服务提供商，包括SpaceX星链（AS14593）、字节跳动（AS396986）、迪士尼全球服务（AS23344）以及Zscaler（AS62044）等。监测显示，BGP路由更新消息在高峰时段激增至每秒15万条以上，远超正常的2-3万条/秒。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljL8iaJ5AWpCZUDhDbLLbTdxZ0vRZXdeUlfaUJg8FibbScsnIm7zYjQibFSywVLybYqIibY3Z956qxS8g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
此次事件进一步表明，互联网核心协议的实际运行仍存在重大隐患。2023年曾有专家撰文警告BGP错误处理的缺陷可能引发全球性问题，而此次故障印证了这一预测。  
  
目前尚无明确的证据指向事件源头，但初步分析表明，Starcloud（AS135338）或和记环球电讯（AS9304）可能是异常路由通告的起始点，部分涉及的前缀包括156.230.0.0/16等。由于和记电讯连接了大量互联网交换中心（IX），而IX普遍使用的Bird软件未对BGP Prefix-SID属性进行过滤，导致问题进一步扩散。  
  
此次事件再次突显互联网基础设施的脆弱性。随着越来越多的关键服务（如应急通信、广播电视等）依赖IP网络，BGP协议实现的差异可能引发远超"用户无法访问电子邮件"的严重后果。网络运营商应及时审查设备配置，启用严格的BGP过滤策略，以避免类似事件重现。  
  
**苹果五年拦截90亿美元欺诈交易 应对App Store日益严峻的安全威胁**  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/3xxicXNlTXLicMWlWUs3WLPqv5Yf65mrYUUoBkWIyZN0Wmic4w1cuPYjEx2RqMTU4TKhwW76wG3m5FMZZvgLSzWaw/640?wx_fmt=jpeg&from=appmsg "")  
  
苹果公司周二披露，过去五年间已阻止超过90亿美元的欺诈交易，其中仅2024年就拦截逾20亿美元。该公司表示，App Store正面临各类威胁，包括"窃取个人信息的欺诈性应用"和"试图利用用户的虚假支付方案"等多样化欺诈手段。  
## 开发者与账户管控措施  
  
这家科技巨头透露，因欺诈风险已终止46,000余个开发者账户，并额外拒绝139,000个开发者注册申请，以阻止不良行为者提交应用。2023年，苹果还关闭了近118,000个开发者账户。  
  
在用户账户层面，该公司去年拒绝了7.11亿个客户账户创建请求，并停用近1.29亿个现有账户，旨在阻断这些账户从事恶意活动，如垃圾信息传播或通过操纵评分评论、排行榜及搜索结果危害App Store生态完整性。  
## 2024年度关键安全数据  
  
苹果公布的2024年其他重要统计数据包括：  
- 在盗版应用市场检测并拦截10,000余款非法应用，含恶意软件、色情应用、赌博应用及App Store正版应用的盗版版本  
  
- 阻止460万次试图安装或启动非App Store或授权第三方市场分发应用的行为  
  
- 因安全、可靠性、隐私违规或欺诈问题拒绝190万次应用提交  
  
- 下架37,000余个涉及欺诈的应用，拒绝43,000余个包含隐藏或未声明功能的应用提交  
  
- 拒绝320,000次抄袭应用、垃圾应用或误导用户的应用提交，另因隐私违规拒绝400,000次应用提交  
  
- 从App Store排行榜移除7,400余个潜在欺诈应用，并在搜索结果中屏蔽9,500余个欺骗性应用  
  
- 清除App Store中1.43亿条虚假评分与评论  
  
- 识别近470万张被盗信用卡，并永久禁用160万个存在欺诈交易的账户  
  
## 行业对比与监管背景  
  
相较而言，苹果2023年阻止约18亿美元潜在欺诈交易，2022年则拦截超20亿美元。此次披露正值苹果面临对其App Store政策日益严格的审查之际。近期美国法院裁决要求iPhone制造商允许iOS应用显示引导用户在App Store外完成购买的链接或按钮。  
  
今年早些时候，谷歌也发布类似报告称，2024年已阻止236万款违反政策的Android应用上架Google Play，并封禁158,000余个试图发布恶意应用的开发者账户。  
  
  
  
> **文章来源 ：环球时报、安全圈、freebuf******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  
