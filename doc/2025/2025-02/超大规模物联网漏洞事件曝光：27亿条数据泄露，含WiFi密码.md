#  超大规模物联网漏洞事件曝光：27亿条数据泄露，含WiFi密码   
AI小蜜蜂  FreeBuf   2025-02-15 02:05  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgiaaYVJw3o7jceTVekQTmqA2yibNf8c92cVbOsAjdh6HLBZyohNCFelHg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
近日，一场规模巨大的物联网（IoT）安全漏洞事件曝光了27亿条包含敏感用户数据的信息，其中包括Wi-Fi网络名称、密码、IP地址和设备标识符。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgN8laibYXKODwyGcF1lOicwwy9EWGt0CYgOGhrsOAOT8sibAtVWCQRRdNQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
此次事件与一家植物生长灯制造商Mars Hydro以及加州注册公司LG-LED SOLUTIONS LIMITED有关。  
网络安全研究人员Jeremiah Fowler发现了未受保护的数据库，并向vpnMentor进行了报告。  
这一事件凸显了物联网设备安全和云存储实践中的严重漏洞。  
  
  
这个公开可访问的数据库总计1.17TB，没有任何密码保护或加密措施。它包含了全球售出的物联网设备的日志、监控记录和错误报告，具体内容包括：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgZjYPTroAZmhHrmWAOBWf8u5efLIRB3OgSu0eKLPfzicEoj8XzCG96dA/640?wx_fmt=jpeg&from=appmsg "")  
  
泄露的详细信息（来源：VPNMentor）  
  
- Wi-Fi SSID（网络名称）和明文密码。  
  
- IP地址、设备ID、MAC地址和操作系统详细信息（iOS/Android）。  
  
- API令牌、应用程序版本以及标有“Mars-pro-iot-error”或“SF-iot-error”的错误日志。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgicpmxjOMx4Cl1aIOnYjdoueR43I2GuXIVicMByzgiaFgdSYMJ0zSCbfZw/640?wx_fmt=jpeg&from=appmsg "")  
  
Wi-Fi密码（来源：VPNMentor）  
##   
  
**事件背景与调查**  
  
  
## Mars Hydro的Mars Pro应用程序用于控制物联网生长灯和气候系统，尽管其隐私政策声称不收集用户数据，但据报道，该应用程序仍然收集了这些数据。  
  
  
进一步的调查发现，这些记录与加州注册公司LG-LED SOLUTIONS LIMITED有关。泄露的数据还包括API详细信息以及LG-LED SOLUTIONS、Mars Hydro和Spider Farmer公司的URL链接，这些公司生产和销售农业生长灯、风扇和冷却系统。  
  
  
许多记录标有“Mars-pro-iot-error”或“SF-iot-error”，其中包含令牌、应用版本、设备类型和IP地址以及SSID凭证。  
  
  
Fowler迅速通知了LG-LED SOLUTIONS和Mars Hydro，几小时后，数据库的访问权限被限制。Mars Hydro确认，“Mars Pro”应用程序是他们的官方产品，该应用在iOS和Android平台上支持多种语言。  
  
  
然而，目前尚不清楚LG-LED SOLUTIONS是否直接管理该数据库，或者是否使用了第三方承包商。数据库曝光的时间长度以及是否有未经授权的方访问过它也不得而知。  
  
  
**安全风险与影响**  
  
  
  
泄露的数据带来了严重的风险：  
  
1. **网络渗透**：攻击者可以利用暴露的Wi-Fi凭证访问家庭或企业网络，从而实施中间人攻击、数据拦截或勒索软件部署。  
  
1. **僵尸网络招募**：受感染的物联网设备可能被劫持用于DDoS攻击，正如最近涉及Matrix黑客组织的事件所示。  
  
1. **物理威胁**：恶意行为者可能操纵连接的生长灯、风扇或冷却系统，从而可能破坏农作物。  
  
Fowler特别强调了“最近邻攻击”这种战术的可能性，这是俄罗斯GRU黑客在2024年通过附近Wi-Fi网络入侵一家乌克兰组织的策略。  
  
  
Palo Alto Networks的威胁报告为此提供了背景：98%的物联网设备数据未加密，57%的设备高度脆弱。  
  
  
此次事件反映了物联网安全中的系统性缺陷：  
  
- **弱加密**：许多设备依赖如WPA2等过时的协议，这些协议容易受到暴力破解攻击。  
  
- **默认密码**：用户往往未能更改出厂设置，导致设备暴露在风险中。  
  
- **集中化云存储风险**：在未受保护的服务器上存储大量数据，创造了单点故障。  
  
值得注意的是，研究人员猜测此次泄露可能涉及2019年由中国智能设备品牌Orvibo暴露的同一数据库。  
  
  
专家们敦促物联网制造商和用户采取以下措施：  
- **加密敏感日志**，并用令牌化值替换明文凭证。  
  
- **分割网络**，将物联网设备与关键系统隔离。  
  
- **进行定期审计**和渗透测试。  
  
Mars Hydro和LG-LED SOLUTIONS尚未就此次泄露事件的起源或可能的第三方参与发表评论。Fowler强调，他的发现旨在“提高人们的意识”，目前没有证据表明存在直接滥用行为。  
  
  
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
  
