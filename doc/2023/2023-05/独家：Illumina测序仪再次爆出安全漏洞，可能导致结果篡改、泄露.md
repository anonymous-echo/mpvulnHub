#  独家：Illumina测序仪再次爆出安全漏洞，可能导致结果篡改、泄露   
 网络安全应急技术国家工程中心   2023-05-06 14:48  
  
**全球视野，深度视角**  
  
各位股东，大家早上好中午好下午好晚上好。  
  
感谢各位股东的倾情付出，咱们MGI的文章阅读量已经突破了1w+！  
  
这对于咱们一个创办不久的小小自媒体来说，是一个重要的里程碑。  
  
也感谢一路走来各位股东的不离不弃，谢谢大家！希望大家在接下来的假期好好玩玩，多多快乐！  
  
呃，我可能会继续内卷一下下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgbsuGb6yhwVMibic61rx3wUpJuUwwutorbOmVYucZ1HicOrjLhwjzgia59w/640?wx_fmt=png "")  
  
**那么，今天要恭喜NovaSeq X Plus在国内用户们喜提新机，也恭喜即将使用这批测序仪的客户朋友们，可以有新玩具了。**  
  
不过，美国时间2023年4月27日，Illumina还有一件事情需要跟大家聊聊。  
  
截至发稿时，国内并没有任何自媒体平台提及（经查，确有其他同仁抢先，但没我深度，狗头），但是广大Illumina用户有必要知道一下。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/nq0D7yqtNUTKoZzmHFQsfy5JlFCfsYeI6vzZ8btQk3odu7eKQYYazwvq8aovCay4XWtaXaNoV1D5tic0K2NqwBw/640?wx_fmt=png "")  
  
漏洞再现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5scbhKFddXonaGVRuicxMsUXBEwjP9eyX5qrh4ibM1OXWeGmhicm9miaBeWE19FgSv3uYYLzxjRZKTJ85jnnvibZwnQ/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgavpgM4hLZHWGVpjKuzgP918OAvvXSdibbT99Ry6fcVibBwDXFial1KUDg/640?wx_fmt=png "")  
  
**2023年4月27日，美国联邦食品药品管理局（FDA）发布公开信，警告健康管理机构Illumina的通用拷贝服务软件可能导致患者检测和客户网络风险。**  
  
这个翻译比较拗口，说人话就是Illumina的一款名为**Universal Copy Services（UCS）的软件**存在漏洞。  
  
而这，已经不是Illumina第一次发生如此高等级的软件安全漏洞事件了。  
  
[](http://mp.weixin.qq.com/s?__biz=MzU3OTYwNjk1NA==&mid=2247483748&idx=1&sn=5895abb701a327020621a2cc33269389&chksm=fd62c1a1ca1548b7aada76fb23959ec59e6dafe42ebbc109f966ff9dfd37edd241120346e63c&scene=21#wechat_redirect)  
  
2022年6月15日，循因缉药公众号独家披露了Illumina测序仪LRM（Local Run Manager,本地运行管理器）漏洞的全面解析。  
  
感兴趣的朋友可以点击图片了解，顺便看看当年还稚嫩的语言组织能力。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nq0D7yqtNUTKoZzmHFQsfy5JlFCfsYeI6vzZ8btQk3odu7eKQYYazwvq8aovCay4XWtaXaNoV1D5tic0K2NqwBw/640?wx_fmt=png "")  
  
**漏洞细节**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5scbhKFddXonaGVRuicxMsUXBEwjP9eyX5qrh4ibM1OXWeGmhicm9miaBeWE19FgSv3uYYLzxjRZKTJ85jnnvibZwnQ/640?wx_fmt=png "")  
  
  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgzoxcHxvzicqSiasvtpFb03ibue5jP2staW6osKmCDpjxaRU2JQ77sV7YA/640?wx_fmt=png "")  
  
美国国土安全部下属网络安全和基础设施安全局 (CISA)发布了工业控制系统医疗设备公告(Industrial Controls Systems Medical Advisory，ICSMA)。  
  
**CVSS v3（Common Vulnerability Scoring System Calculator，通用漏洞评分计算系统）评分 10分，严重（最高级别）。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUg613a6y8Gv3GTTgZkA8lZE2qU8fPEyWh9rgln6icAPJVVqB88lA3Ne7g/640?wx_fmt=png "")  
  
**受影响软件和版本：**  
- iScan Control Software: v4.0.0  
  
- iScan Control Software: v4.0.5  
  
- iSeq 100: All versions  
  
- MiniSeq Control Software: v2.0 and newer  
  
- MiSeq Control Software: v4.0 (RUO Mode)  
  
- MiSeqDx Operating Software: v4.0.1 and newer  
  
- NextSeq 500/550 Control Software: v4.0  
  
- NextSeq 550Dx Control Software:  v4.0 (RUO Mode)  
  
- NextSeq 550Dx Operating Software:  v1.0.0 to 1.3.1  
  
- NextSeq 550Dx Operating Software: v1.3.3 and newer  
  
- NextSeq 1000/2000 Control Software: v1.7 and prior  
  
- NovaSeq 6000 Control Software: v1.7 and prior  
  
- NovaSeq Control Software: v1.8  
  
也就是说不仅仅测序系统除了最新的NovaSeq X全线陷落，包括  
**iSeq、MiniSeq、MiSeq（含Dx）、NextSeq 500/550（含Dx）、NextSeq 1000/2000、NovaSeq 6000。**  
  
连芯片系统的  
iScan也难逃厄运，一并受到了影响。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgaQKaibiclnL6l7b6xeXyR5Hhjps9qQfJP67LfyhcVpx2g1c87iaaEyWWA/640?wx_fmt=png "")  
  
**主要危害**：  
  
**第一，远程控制系统；**  
  
**第二，修改设备控制电脑的设置、软件或数据甚至客户的网络；**  
  
**第三，修改基因测序数据，可能导致设备无法出具结果、错误的结果、修改的结果甚至数据泄露。**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/nq0D7yqtNUTKoZzmHFQsfy5JlFCfsYeI6vzZ8btQk3odu7eKQYYazwvq8aovCay4XWtaXaNoV1D5tic0K2NqwBw/640?wx_fmt=png "")  
  
缓解措施  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5scbhKFddXonaGVRuicxMsUXBEwjP9eyX5qrh4ibM1OXWeGmhicm9miaBeWE19FgSv3uYYLzxjRZKTJ85jnnvibZwnQ/640?wx_fmt=png "")  
  
  
  
**请立即访问Illumina提供的推荐指南网站（注3）**  
，并且根据FDA的说法Illumina提供了补丁来解决这个问题，虽然我没找到。  
  
（本来想提供更详细点的信息，方便大家使用，结果Illumina让我登录，呵呵）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUg30PdOLSzLicYKztp1IyhluM561Du8eU2kibEeiarRDRUI50zO32EupwEQ/640?wx_fmt=png "")  
  
想学习学习，都不给机会啊，谢谢Illumina。  
  
另外，Instruction除了英文外，包含多语种，包括日语、阿拉伯语等，不包括汉语、韩语。  
  
不过，这难不倒咱们，欢迎各位及时联系Illumina技术支持，顺便电话费让报销下（狗头）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgDT1HQ1bACsibics0Z7PVsNuibH5QXd2MN5yCpVY296R0mkrScLJKOsNow/640?wx_fmt=png "")  
  
根据我们自己技术小组推测，**应该是UCS的服务在安装时采用的管理员账户，因此漏洞被利用后将取得操作系统权限，进而造成了测序仪控制电脑的失控。**  
  
NovaSeq 6000的示例可以通过  
注4的链接获取，当然更推荐联系Illumina官方，这里仅为预防措施，预防下总不会错。  
  
**小知识：UCS是个啥**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgD8MYgUFZ7alB6cicNok4CWGOx3GnhWKiaaOx7Jf7GzwOw9RSn7ibayGibw/640?wx_fmt=png "")  
  
以NovaSeq 6000为例，Illumina的测序仪机载软件包含三个部分：  
  
NovaSeq Control Software（NVCS）：这是一个引导软件，帮助用户正确的上样（包含部分设置）和加载试剂耗材，并且在运行的时候提供统计数据。  
  
Real-Time Analysis（RTA）：核心组件，提供图像识别和base calling。  
  
Universal Copy Services（UCS）：将RTA和NVCS输出的数据和log复制到输出文件夹中，可以是本地也可以是远程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgk2Mdhpy9ImX88icvrsdqWRciaKQl7ybmGiadWdfJ53YqfXq29DlVFqTmQ/640?wx_fmt=png "")  
  
根据描述，UCS表现形式是Windows或Linux操作系统中的一个服务。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/nq0D7yqtNUTKoZzmHFQsfy5JlFCfsYeI6vzZ8btQk3odu7eKQYYazwvq8aovCay4XWtaXaNoV1D5tic0K2NqwBw/640?wx_fmt=png "")  
  
最后  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5scbhKFddXonaGVRuicxMsUXBEwjP9eyX5qrh4ibM1OXWeGmhicm9miaBeWE19FgSv3uYYLzxjRZKTJ85jnnvibZwnQ/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icugQvAnqxTpickB7sxYOXBSf0lsof5icUgOGnQTI4G8Y7aoO3M12PibOROQ1m3At6f0R2icF09jGWZByo0pfpcJLCQ/640?wx_fmt=png "")  
  
根据FDA信息，本次漏洞由Illumina于2023年4月5日发现并报告。  
  
目前，FDA和Illumina并未受到该漏洞被利用的报告。  
  
我们的建议与CISA类似，那就是：  
- **第一，核心生产设施不要接入外网；**  
  
- **第二，企业必须接入防火墙；**  
  
- **第三，如果需要远程操作，建议使用安全的VPN，并对VPN的安全性定期评估。**  
  
同时，由于并不清楚Illumina是否与NMPA进行了相应的沟通，**建议由Illumina官方尽快通知所有用户进行处理**。  
  
最后，我们**建议其他测序仪厂商，比如华大智造、真迈等市场保有量较高的厂商开展自查**，并及时与客户同步信息。  
  
（完）  
  
**近期文章****：**  
  
**一个王朝的背影--Illumina的2023Q1******  
  
**华大智造超越Illumina成中国区市场份额第一！加大研发/营销，走向世界吧！******  
  
******Bionano|我有一个好消息，还有一个坏消息，你想先听哪一个？******  
  
******思维实验室|假如NGS领域没有华大智造******  
  
******第七封！Carl Icahn与Illumina的纠葛大戏继续上演******  
  
**手术机器人的生意可还行？Intuitive 2023年Q1营收破17亿美元**  
  
**Foundation Medicine裁员135人**  
  
******股东们，投票了！Illumina股东大会日期确认（顺带FTC案子进展）******  
  
**调高财务指引也难逃，医疗器械巨头Medtronic（美敦力）裁员**  
  
**卖到全世界！Element全球多个区域代理商确认！**  
```
注1：https://www.fda.gov/medical-devices/letters-health-care-providers/illumina-cybersecurity-vulnerability-affecting-universal-copy-service-software-may-present-risks
注2：https://www.cisa.gov/news-events/ics-medical-advisories/icsma-23-117-01
注3：：https://support.illumina.com/downloads/illumina-universal-copy-service-1-0.html
注4：https://knowledge.illumina.com/instrumentation/instrument-administration/instrumentation-instrument-administration-reference_material-list/000007852
```  
  
  
