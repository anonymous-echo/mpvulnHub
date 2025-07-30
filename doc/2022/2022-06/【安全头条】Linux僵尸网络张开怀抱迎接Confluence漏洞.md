#  【安全头条】Linux僵尸网络张开怀抱迎接Confluence漏洞   
安全客  安全客   2022-06-10 10:36  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4bicLm4aSkdIN1cXw6siaXXuxrO2wuUhjhxGT2H4778DoP4DwJXGYUkg9GMjApbAuibtBmUpDfxnTibw/640?wx_fmt=jpeg "")  
  
**第298期**  
  
**你好呀~欢迎来到“安全头条”！如果你是第一次光顾，可以先阅读站内公告了解我们哦。****欢迎各位新老顾客前来拜访，在文章底部时常交流、疯狂讨论，都是小安欢迎哒~如果对本小站的内容还有更多建议，也欢迎底部提出建议哦！**  
  
##   
## 1、Linux僵尸网络  
## 张开怀抱迎接  
## Confluence漏洞  
  
安全研究员监测到部分僵尸网络开始用Confluence漏洞扩大地盘，感染Linux服务器。   
自该漏洞PoC发布后，某安全公司发布报告漏洞主动利用从23个增加到200多个增长近十倍。而这些僵尸网络中，又属Kinsing、Hezb和Dark.IoT最为过分，感染后发发DoS攻击就算了还疯狂挖矿。   
  
虽然不算是安慰，但相比log4j或apache这种规模的漏洞，Confluence的利用已经算相当收敛了，所以运维躺平的阈值还是很高的。当然，该修肯定还是要修的，哪天上一个勒索软件那就bbq了。  
[点击“阅读原文”查看详情]  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4bicLm4aSkdIN1cXw6siaXXuEvicMiccbv3oFMTCSlXiaJ4YUv9MsBAXYd8Yb6QtxcMIHpVPulhIc9gUQ/640?wx_fmt=jpeg "")  
  
## 2、Kali Linux  
## 团队渗透课堂开课啦  
  
Kali Linux创立者Advolation Security宣布将于本月末上线免费渗透测试教程——使用Kali Linux进行渗透测试“PEN-200/PWK”。  
  
该课程最早是为OSCP认证考试设计的，因疫情线下课程中断后，改为线上远程授课，随着流程逐渐完善，最终决定将这份内容打造为“OffSec Live”网络安全教育平台，并通过Twitch进行直播。当然，钱还是要想办法赚的，虽然每周两次，每次一个小时的PEN-200直播课程是免费的，但只有注册了的学生才能登录Offensive Security实验室与下载培训资料。总的来说是一次成功的营销。  
[点击“阅读原文”查看详情]  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4bicLm4aSkdIN1cXw6siaXXuxZgbUMnQc4yeHBno22OcoXmAt7ur2FcwaF1V33HeMuD1G2MAd45FTg/640?wx_fmt=jpeg "")  
  
## 3、大规模Facebook  
##  Messenger钓鱼活动  
## 骗取数百万美元  
  
最近有一起大规模的Facebook Messenger钓鱼攻击引起了安全社区的注意，此攻击已狂揽数百万美元。  
  
它的玩法还是有一点“复古”的，窃取受害者账号密码后，就疯狂给受害者弹广告，还登录上去以受害者名义给其他联系人发钓鱼链接。据统计，21年9月钓鱼网站上线，于22年4至5月达到顶峰。后面传播的风风火火可以理解，但安全研究员还没弄清楚最初的受害者是通过什么方式中招的，初步猜测是通过重重定向的钓鱼页面广撒网攻击成功。虽然FB对钓鱼链接有防范，但面对这种利用URL生成跳转的就无能为力了。安全研究员意外拿到了钓鱼网站的统计数据访问权限，发现21年共270万用户访问了钓鱼网站，22年这个数字突破了800万，增长迅速，已是相当庞大的规模，收入少说也有几百万美元。  
[点击“阅读原文”查看详情]  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4bicLm4aSkdIN1cXw6siaXXuZ93TftgOFHQLCuE164QmOWK3iaHX8aaY3EwkXxjZ4Z8zfHVoibYhr1oQ/640?wx_fmt=jpeg "")  
  
## 4、Cuba勒索软件  
## 强势回归还搞了新变种  
  
Cuba勒索软件去年于Hancitor恶意软件组织合作破坏近50个关键基础设施，今年年初却没有了声息，但4月突然带着新变种强势回归。   
近期Cuba又在其Tor数据泄露站上更新了4、5月的受害者，但安全圈认为攻击恐怕发生在很早前，恐怕Cuba目前的策略是集中精力攻击给得起赎金的超大型企业或关键基础设施而不是胡乱攻击便宜要价。新变种的出现印证了这一猜想，无利不起早，他们依然活跃的事实说明相比摸鱼划水更有可能是秘而不宣。  
  
考虑到他们的针对性和技术水平，大型企业要对其尤其关注，多加防范。  
[点击“阅读原文”查看详情]  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4bicLm4aSkdIN1cXw6siaXXu1kMSUH440Gkn39fHQiaXmibV1KrGby9EcbEqO8gdYzDnGTuojicBicKibKA/640?wx_fmt=jpeg "")  
  
## 5、黑客通过谷歌  
## 搜索传播带毒  
## CCleaner  
  
盗版软件一直以来都是恶意软件重灾区，杀毒软件旗下的软件也不例外。Avast旗下的CCleaner Pro盗版版本被魔改为窃取账号密码的恶意软件，受害者遍布法国、巴西、印尼和印度。   
此恶意活动暂被命名为FakeCrack，是由CCleaner的正主Avast发现的，黑客利用SEO，把宣传恶意软件的网站放在搜索结果前列，不少粗心的受害者一着急就点进去还下了。为了让用户放下戒心，黑客还把安装包托管在合法文件托管平台上（虽然正常来说也根本不会这么搞），还给压缩包加上密码逃避杀软检测。  
  
一旦安装成功，浏览器中的账号密码自不必说，连加密货币钱包中的财产都不放过，所以说盗版软件害死人。  
[点击“阅读原文”查看详情]  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4bicLm4aSkdIN1cXw6siaXXu4NpDw99LLhTticgxlMtiatG7QxIia69KnY77vibjs1ZP3koHGsqZN6OMUQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ok4fxxCpBb7QxxODhJSnPyIZe6ZNAgPibByWLDwGu5SWicFr0g9FbXs5Ffdsx3EibAuPaf8njVefjA9B54oHsRqwg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7QxxODhJSnPyIZe6ZNAgPibsxfq5yL6kPEIaGDzibzV1W1QWNXic8dnx3Ky93Ay7PEpb7lgYGREddkA/640?wx_fmt=png "")  
  
上期回顾  
  
[【安全头条】美国封杀涉嫌贩卖2400万人信息的SSNDOB市场](http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&mid=2649771392&idx=2&sn=27ef49ec19892f7a992ac3e3f7183013&chksm=88937defbfe4f4f9838e9d1213fe3ea65966918c62ec8348eec5d05ce301e8848e4267b24e16&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ok4fxxCpBb5ZMeq0JBK8AOH3CVMApDrPvnibHjxDDT1mY2ic8ABv6zWUDq0VxcQ128rL7lxiaQrE1oTmjqInO89xA/640?wx_fmt=gif "")  
  
**戳“阅读原文”查看更多内容**  
