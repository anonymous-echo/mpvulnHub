#  KCon演讲议题巡展｜闭源安卓系统下的漏洞自动化发现之旅   
Hearmen  KCon 黑客大会   2023-08-03 11:30  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AlyXhptkzjibib23iaQyUSxNbQ4jJq0usY5Yia5eUO5QeO83VE8MYeDlVSw/640?wx_fmt=jpeg "")  
  
“归源·智变” 2023年KCon黑客大会  
  
举办时间：2023年8月19日-20日  
  
举办地点：北京环球贸易中心·会议中心  
  
  
[KCon 2023 演讲议程已尘埃落定](http://mp.weixin.qq.com/s?__biz=MzIzOTAwNzc1OQ==&mid=2651136447&idx=1&sn=64206408e5de7f627607443d5df5389c&chksm=f2c120dfc5b6a9c9f162887f0140161d2bc4a947f56f3999e80c2912433e5a1a0bc165e6dfd4&scene=21#wechat_redirect)  
  
  
为展示演讲议题风采  
  
帮助大家更好地了解议题  
  
  
特此开展  
  
**KCon 2023演讲议题巡展活动**  
  
欢迎朋友们围观  
  
* 议题展示顺序以议程先后顺序为准～  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AOYicibPibJB2J0GJM1mYISDc9K1yOqhzWZvibeyesBNmG7YIiaicXMDWcrkQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AHnEYO7Ug1qmPapk6qiabicGqOM8xlGWcGZREVpaz4eP0e1zk9kicvbkeQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AOYicibPibJB2J0GJM1mYISDc9K1yOqhzWZvibeyesBNmG7YIiaicXMDWcrkQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6ADIQkmwGg8F0l4icfVibiaexzk18DryrE3eicHgczbmwXGW0key3FaV9Zng/640?wx_fmt=png "")  
  
**演讲议题**  
  
  
**闭源安卓系统下的漏洞自动化发现之旅**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6ADIQkmwGg8F0l4icfVibiaexzk18DryrE3eicHgczbmwXGW0key3FaV9Zng/640?wx_fmt=png "")  
  
**演讲人：Hearmen**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AEnDQaoa2r0iaicfZmlFGUibV4bUV1YxW00rbCjNva8hEuFcWoxV0nSuYA/640?wx_fmt=jpeg "")  
  
  
秦策（hearmen），望潮实验室（南京）负责人。专注移动安全、应用安全、二进制，BlackHat、Defcon、HITB、KCon 2015演讲者。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6ADIQkmwGg8F0l4icfVibiaexzk18DryrE3eicHgczbmwXGW0key3FaV9Zng/640?wx_fmt=png "")  
  
**演讲人谈议题**  
  
  
在过去的十年中，EvilParcel 漏洞对于Android安全构成了严重威胁。通过构造 EvilParcel，攻击者可以在受攻击的应用程序或系统组件上触发内存破坏、提权或远程代码执行。尽管Android 13使用LazyValue来防御这种类型的漏洞，但由于Android生态系统的碎片化，主要手机厂商仍然面临着这种漏洞的威胁。  
  
  
CodeQL是一种先进的代码分析引擎，使研究人员可以像处理数据一样查询代码。CodeQL可以通过使用其定制化的查询语句在大型代码库中发现复杂的漏洞。然而，将CodeQL应用于商场的闭源系统是一个重大的挑战，因为我们无法获取到目标系统的源代码。  
  
  
本演讲中，我们提出了CodeQL和ChatGPT两个强大工具的新颖组合，用于在闭源Android系统中查找EvilParcel漏洞。我们通过对CodeQL原理的分析，实现了一套辅助工具，可以根据厂商的系统framework创建对应的CodeQL数据库，而无需访问源代码。然后我们就可以使用定制化的QL查询语句来识别潜在漏洞。并使用ChatGPT与查询结果进行交互，生成进一步分析的建议。除了闭源系统之外，我们的方案还可以应用到其他的安卓应用和java开发的服务端应用中，具备强大的可扩展性。  
  
  
我们通过CodeQL和ChatGPT在很短的时间内在多个闭源系统中发现了10+EvilParcel漏洞。我们已将这些漏洞报告给了各自的厂商，并得到了确认。但这仅仅是开始，我们相信，CodeQL和ChatGPT在漏洞挖掘和漏洞利用上具备强大的潜力，希望我们的演讲能够为更多的安全研究人员和从业者提供工具使用的思路，共同建设良好的安全环境。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6ADIQkmwGg8F0l4icfVibiaexzk18DryrE3eicHgczbmwXGW0key3FaV9Zng/640?wx_fmt=png "")  
  
**演讲时间**  
  
  
2023年8月20日 9:00-9:30  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AT6D8q1tYSsiasVQhXy0vVIfm6Y4czg8FiaLlC8joR2e4N303T7icicsX0g/640?wx_fmt=jpeg "")  
  
本届KCon大会为线下会议，**无**线上视频直播，敬请知悉！购票方式如下：  
  
**KCon 2023 门票**  
  
  
  
**购票网址：**  
  
**https://www.4hou.com/tickets/aADO**  
  
****  
**长按识别下方二维码**或  
  
点击文末“**阅读原文**”  
  
立即购票  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6A5mdUz6Ev68wY8ibRANCdraWWic2goq11N8fstOibwyPSp0uFmgHoqQAZA/640?wx_fmt=png "")  
  
● 学生票：410元（需提供相关证明）  
  
● 团队票：1434元（3张起购）  
  
● 普通票：2048元  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/e5by8a5GzIb1JiaCt7dibNhNDOeFq17G6AXHCTaYaoZFDFj754E2DyqWAf5RqZhia7bxNHyXJ4WZQ1gXCkCxcwvJw/640?wx_fmt=jpeg "")  
  
**点击阅读原文**  
  
**立即购票**  
  
