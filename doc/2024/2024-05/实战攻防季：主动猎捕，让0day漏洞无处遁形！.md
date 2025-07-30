#  实战攻防季：主动猎捕，让0day漏洞无处遁形！   
智安全  深信服千里目安全技术中心   2024-05-22 17:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5hMJDgFiaBZFHnic1iaPKWZ51uUhD7TnPM24RwRHIB9BZp8ibqQHkxIx1tqarKGOnG9XXJ2U94ABrQ1lUr8XdMDMSA/640?wx_fmt=gif "")  
  
**2024实战攻防演练**即将开启。  
  
  
伴随网络安全形势日益复杂，攻击方的攻击手段不断升级，0day漏洞的利用也愈发频繁，成为防守方必须警惕的**“隐形陷阱”**。在实战较量中，防御一旦出现滞后则可能带来严重的安全风险。  
  
  
2023 年深瞳漏洞实验室猎捕到**100+**个 Web 场景下的在野利用 0day 漏洞，其中**50%** 以上出现在实战攻防演练场景中，下表列举了去年影响较大的0day漏洞。各防守单位也可加强注意，实战攻防演练期间，**一定要对历史漏洞进行提前检测并加强防护，做好0day攻击的主动猎捕和快速处置。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaByU9kYV8HwwZgBmBRwGqyWPzicf5A7MY2VJ768TTzeneByJRze6bCHdbA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
以上内容出自由深信服千里目安全技术中心深瞳漏洞实验室出品的**《2023漏洞威胁分析报告》**，报告基于对2023年全球漏洞情况的跟踪与分析，全面梳理了漏洞威胁的数量、类型、危害的全貌，对2024漏洞威胁的发展趋势和特点做出研判，并提出应对漏洞威胁的针对性思路和解决方案。  
  
  
**- 报告共 51 页，扫文末二维码可免费获取 -**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kolxCZk5Bibicxzs9pQmCJn9yAIibCktBqMibJONmOxRnhmNrhOg5uVwyzRZibicXN1StQPFhauHBGfFtUg/640?wx_fmt=png&from=appmsg "")  
  
**一组“数据清单”窥见漏洞威胁演变趋势**  
  
国  
家信息  
安全漏洞库（CNNVD）数据显示，漏洞收录数量在逐年增长，  
超危漏洞占比呈上升趋势，**高危和超危漏洞占比超过了50%**  
。  
根据近10年已知漏洞情况分析，95% 以上被利用漏洞是 2023 年以前漏洞，未修补的漏洞仍在被黑客持续利用。  
2024年，漏洞攻势必将愈发凶猛，各企事业单位对于已发现和存在的漏洞都有必要及时处置，避免造成更严重损失。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaBydJxe3adEylia0RHWyc1PIJ1wAAeuJJ6rTEAlLibYYQYb0nRjmjibLRcTg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
国家信息安全漏洞共享平台（CNVD）数据显示，在过去五年中，Web 应用漏洞的比例在持续上升，应用程序漏洞的比例则逐步下降，网络设备漏洞的比例略有增加，操作系统漏洞的比例则略有减少。2023年 已 知 被 利 用 漏 洞（KEV）目 录 和 谷 歌 跟 踪 0day漏 洞 利 用 名 单显示，被利用漏洞数量最多的产品是Windows。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaByDHF95jZv6j9PnLSOJGhIKlPHshp6nXgA5R887ABPuI7Eft6KFy9XuQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**2023年，我国由安全漏洞引发的威胁趋向于破坏性攻击。**信息泄露和管理员访问权限获取成为最主要的两大威胁。未授权的信息泄露，可能严重侵犯个人隐私，引发财务损失，损害商业信誉，甚至触发法律诉讼。攻击者一旦通过漏洞获取管理员权限，便能够完全掌控系统，访问敏感数据，修改系统配置，进行任意操作。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaByuiapC0rUIElyU5fW1bkGLb38g7iacZIWsm5vA01vUZEaIR4uficMh1r9w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kolxCZk5Bibicxzs9pQmCJn9yAIibCktBqMibJONmOxRnhmNrhOg5uVwyzRZibicXN1StQPFhauHBGfFtUg/640?wx_fmt=png&from=appmsg "")  
  
**0day漏洞成为攻防对抗中的“隐形陷阱”**  
  
  
202  
3年，**0day漏洞利用数量显著增加**  
。  
谷歌团队分析，在过去十年中，尤其是最近三年，0day 漏洞的在野利用事件明显增长，因为黑客利用 0day 漏洞进行攻击时能够有效规避现有的安全防护措施，从而大幅提升攻击的成功率。  
网络安全面临的威胁日益严峻，  
**建立并提升自身的0day漏洞攻击猎捕能力**  
对各企事业单位的安全来说至关重要。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaByeg1Z0EoxnCbWrP6tmLauk0MCvict6SCA57eYdiaAUxwqZJFABTO36PVg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
2023年，深瞳漏洞实验室猎捕到的100+个Web场景下的在野利用0day漏洞，其中**一半以上出现在攻防演练场景中**。可见高可利用 0day 漏洞依然是攻防场景下的主力军，其中弱口令、信息泄露漏洞是横向移动主要的漏洞， 其次是SQL 注入漏洞、API 访问控制漏洞。随着攻防对抗常态化，将会有越来越多的 0day 漏洞被利用于网络攻击，必须提升针对0day的猎捕和快速处置能力，以有效抵抗未知的威胁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaByvuntTVjOTyNPbF9NpQvlXTUhzB2ADxnQhCoTUwz2Ovg1vWeGhrTHnw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kolxCZk5Bibicxzs9pQmCJn9yAIibCktBqMibJONmOxRnhmNrhOg5uVwyzRZibicXN1StQPFhauHBGfFtUg/640?wx_fmt=png&from=appmsg "")  
  
**开源软件成为漏洞攻击的“新宠”**  
  
数据显示，2023 年较为热门的漏洞多数为开源软件，例如 Apache ActiveMQ 远程代码执行漏洞、Apache RocketMQ 远程代码执行漏洞、Apache OFBiz 远程代码执行漏洞等，这些在行业内都属于影响较大，危害较高的案例。  
  
  
Synopsys 在 2023 年的报告中分析了 1703 个代码库，其中 96% 包含开源代码，76% 项目全部开源。其中，84% 的代码库至少包含一个已知的开源漏洞，48% 的代码库包含高危漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaByUfs0utf9WCLc75dKbfwMEvD7Oky8exicI6VF09CvF1l6CyFOYScK14g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
由于开源组件是开放的，没有任何形式的保证，使用开源软件会给下游用户带来较高的安全风险。在使用开源软件时，**有必要仔细评估其安全风险，并采取安全措施。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kolxCZk5Bibicxzs9pQmCJn9yAIibCktBqMibJONmOxRnhmNrhOg5uVwyzRZibicXN1StQPFhauHBGfFtUg/640?wx_fmt=png&from=appmsg "")  
  
**智防千里**  
  
**“政策+技术”双重防线抵御威胁**  
  
国家制定了各项法律法规，为数字化建设打下坚实的安全基础。  
为确保国家网络安全和网络产品及关键系统的稳定运行，**《网络安全法》、《网络产品安全漏洞管理规定》**  
等法律法规先后出台。  
相关的信创漏洞国家标准也在制定中，旨在推动漏洞管理工作的制度化、规范化和法治化，提升各责任主体的管理水平。  
  
深信服基于自身持续积累的流量类样本，IP、URL、漏洞等情报数据，安全人员研判知识，进行大模型预训练和微调，构建了安全 GPT 检测大模型。  
**安全 GPT 检测大模型**能够发现混淆、编码类高绕过流量，并针对 Web 漏洞有良好检出效果，具有较强Web 0day 漏洞检测能力，同时针对攻击成功研判具有较高准确率。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaBymGajVq2T4rWMJdMrBI85lmhjeDC5NYNsqc1WN1cYLBLqnUGLz2H0ng/640?wx_fmt=jpeg&from=appmsg "")  
  
  
安全 GPT 检测大模型具备了 HTTP 流量理解能力、代码理解能力、攻防对抗理解能力和安全常识理解能力，类似一个  
**懂攻防、识代码的“虚拟专家”**，致力于针对 0day 等高对抗攻击，实现全覆盖、零绕过，并重点识别传统检测引擎无法发现的高对抗、混淆类未知威胁。  
  
  
网络安全是一场长期的攻防对抗战役。作为网络安全领域的从业者，让我们携手共进，为构建一个更加安全、稳定的网络环境而努力！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9kpxkkNDdI2w4VU5sJjg2iaBysxkAp8ySs4uYtjpia8OoLyzxKFRwTMdkc3qvys6yc8wspUOmqnrK1PA/640?wx_fmt=png&from=appmsg "")  
  
  
**扫码免费领取报告全文电子版****，如需印刷版可联系当地同事。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zFObpGGvbWzxnyX6UtTRfibFXicTzaYOdfAp1NDOmZN6qj1Ib5bMRxNDYTBZTIwzD8DPrs7kS9sPrQ/640?wx_fmt=jpeg "")  
  
  
