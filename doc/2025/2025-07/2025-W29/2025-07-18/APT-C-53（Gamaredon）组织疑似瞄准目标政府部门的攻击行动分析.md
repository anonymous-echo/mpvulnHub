> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyMjk4NzExMA==&mid=2247507128&idx=1&sn=fc52ed41c425b97d96e8aa395b01cb16

#  APT-C-53（Gamaredon）组织疑似瞄准目标政府部门的攻击行动分析  
原创 高级威胁研究院  360威胁情报中心   2025-07-18 10:08  
  
**APT-C-53**  
  
    
**Gamaredon**  
  
APT-C-53（Gamaredon），又名Primitive Bear、Winterflounder、BlueAlpha，是一个自2013年起活跃的高级持续威胁（APT）组织。该组织长期针对目标国家的政府部门、军事机构等重点单位进行攻击，最早攻击活动可追溯至2013年，主要目的为窃取情报等。该组织十分活跃，不断开发各类攻击载荷，包括模板注入文档、宏文档、LNK文件、HTML文件、SFX自解压文件等， 这也加大了安全人员对其进行捕获与追踪的难度。  
  
 一、受影响情况   
  
在我们的观察中，乌克兰的政府职能部门成为了攻击目标，攻击者试图获取乌克兰政府部门的相关信息。  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="330" width="330" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p><b style="mso-bidi-font-weight:normal;"><span style="font-family:仿宋;"><span leaf="" mpa-font-style="md7747q8dap" style="font-size: 16px;" data-mpa-action-id="md7747qv13ea" data-pm-slice="0 0 []">乌克兰语文件名</span><span lang="EN-US"><o:p></o:p></span></span></b></p></td><td data-colwidth="223" width="223" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p><b style="mso-bidi-font-weight:normal;"><span style="font-family:仿宋;"><span leaf="" mpa-font-style="md774biqhct" style="font-size: 16px;" data-mpa-action-id="md774bjan5w" data-pm-slice="0 0 []">中文对照</span><span lang="EN-US"><o:p></o:p></span></span></b></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="330" width="330" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p data-mpa-action-id="md773qo01n32" data-pm-slice="0 0 []"><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="" mpa-font-style="md773qndj27" style="font-size: 16px;">\РАбота полиция\2023\1   документы\ВОГНЕВА\роздавальна ведом</span></span><span mpa-font-style="md773qnd31a" style="font-size: 16px;"><span lang="EN-US" style="font-family:
  &#34;Cambria&#34;,serif;mso-fareast-font-family:DengXian;mso-bidi-font-family:Cambria;"><span leaf="">і</span></span><span style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:DengXian;"><span leaf="">сть</span></span></span><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;"><span leaf="" mpa-font-style="md773qndphm" style="font-size: 16px;">.docx</span><o:p></o:p></span></p></td><td data-colwidth="223" width="223" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p data-mpa-action-id="md7743du1lu3" data-pm-slice="0 0 []"><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="" mpa-font-style="md7743dbo84" style="font-size: 16px;">\</span></span><span style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span mpa-font-style="md7743db1csw" style="font-size: 16px;"><span leaf="">警务工作</span><span lang="EN-US"><span leaf="">\2023\1.</span></span><span leaf="">文件</span><span lang="EN-US"><span leaf="">\ВОГНЕВА\</span></span><span leaf="">分发清单</span></span><span lang="EN-US"><span leaf="" mpa-font-style="md7743db2o9" style="font-size: 16px;">.docx</span><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:2;mso-yfti-lastrow:yes;"><td data-colwidth="330" width="330" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p data-mpa-action-id="md773vsg1og7" data-pm-slice="0 0 []"><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="" mpa-font-style="md773vrve6r" style="font-size: 16px;">\работа+полиция\2023\вк_тексти\2025_тексти\с</span></span><span mpa-font-style="md773vrv111y" style="font-size: 16px;"><span lang="EN-US" style="font-family:&#34;Cambria&#34;,serif;mso-fareast-font-family:DengXian;mso-bidi-font-family:Cambria;"><span leaf="">і</span></span><span style="mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:DengXian;"><span leaf="">чень</span></span><span lang="EN-US" style="mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="">\</span></span><span style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:DengXian;"><span leaf="">болград</span></span><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;"><span leaf="">_</span></span><span style="mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:DengXian;"><span leaf="">закладчиця</span></span><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="">+</span></span><span style="mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:DengXian;"><span leaf="">ст</span></span><span lang="EN-US" style="mso-ascii-font-family:
  DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="">.+307+</span></span><span style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;mso-bidi-font-family:DengXian;"><span leaf="">ч</span></span></span><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:
  DengXian;mso-hansi-font-family:DengXian;"><span leaf="" mpa-font-style="md773vrv1rfv" style="font-size: 16px;">.+2.doc</span><o:p></o:p></span></p></td><td data-colwidth="223" width="223" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p data-mpa-action-id="md77408j19kt" data-pm-slice="0 0 []"><span lang="EN-US" style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span leaf="" mpa-font-style="md774083kl1" style="font-size: 16px;">\</span></span><span style="mso-ascii-font-family:DengXian;mso-fareast-font-family:DengXian;mso-hansi-font-family:DengXian;"><span mpa-font-style="md774083pio" style="font-size: 16px;"><span leaf="">警务工作</span><span lang="EN-US"><span leaf="">\2023\VK_</span></span><span leaf="">文本</span><span lang="EN-US"><span leaf="">\2025_</span></span><span leaf="">文本</span><span lang="EN-US"><span leaf="">\</span></span><span leaf="">一月</span><span lang="EN-US"><span leaf="">\</span></span><span leaf="">博尔格勒</span><span lang="EN-US"><span leaf="">_</span></span><span leaf="">毒品藏匿者</span><span lang="EN-US"><span leaf="">_</span></span><span leaf="">第</span><span lang="EN-US"><span leaf="">307</span></span><span leaf="">条</span><span lang="EN-US"><span leaf="">_</span></span><span leaf="">第</span><span lang="EN-US"><span leaf="">2</span></span><span leaf="">款</span></span><span lang="EN-US"><span leaf="" mpa-font-style="md77408332w" style="font-size: 16px;">.doc</span><o:p></o:p></span></span></p></td></tr></tbody></table>  
  
 二、攻击活动分析   
## 1. 攻击流程分析  
  
Gamaredon组织常用docx文档作为诱饵诱导用户点击查看，文件一旦被打开便会远程加载带宏的恶意文件，其执行时解密释放vbs脚本文件并加载，其脚本主要功能是上传用户基本信息，并通过解析域名拼接URL来下载后续载荷执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PqLibuGO9bug0HJF7jYQ7ekibqo5EBU8TM7krCicJ8O0ngQ47N59KIdHrW7zsTwsSKqQPxMCIicJicQgyg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
2.  
  
恶意载荷分析  
### 2.1 VBS混淆  
  
该组织偏好采用VBS脚本作为下载器、释放器及可持续化控制的手段之一，为了阻碍分析人员的工作，该组织会将脚本中的关键字符串甚至是代码进行破碎和编码，并加入一些垃圾段落来降低脚本的可读性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBniaibicEy0Gyl5lh5vI1Y2GHqeEcIcCibTzllXLKRjWCjUTFYVRVpR4Q6yYA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
大体上代码的混淆思路就是关键字符串拆开，并插入注释的垃圾内容。  
  
对这些混淆严重的脚本进行了解析，其代码只是在拼接出下一段混淆代码，拼接完成后再调用Execute和Eval函数进行执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBnia14bbRfhFLDYOJaj0jQKHNhFpuOF4uV7gSJgMspN9SRVj9j49d9Cgvg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
逐步解析后获得下一段混淆代码，按顺序进行拼接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBniaW4a5h31Z4pxzicA7VL8e7XPQIJGtAYmqdqXaxqYh2fv7czW2wq4HfSA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
接下来只需要通过对几个混淆字符串的替换，并以" yw9UKi8jPKP5 "进行分隔，就可以得到最终的脚本内容。  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="145" width="277" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p><span leaf="" mpa-font-style="md776v2o1jlf" style="font-size: 16px;" data-mpa-action-id="md776v37i8m" data-pm-slice="0 0 []">原字符串</span><span lang="EN-US"><o:p></o:p></span></p></td><td data-colwidth="93" width="277" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p><span leaf="" mpa-font-style="md776zce21y" style="font-size: 16px;" data-mpa-action-id="md776zd11lf4" data-pm-slice="0 0 []">替换为</span><span lang="EN-US"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="145" width="277" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md776snl23py" style="font-size: 16px;" data-mpa-action-id="md776so0oue" data-pm-slice="0 0 []">&#34;AL5X0&#34;</span><o:p></o:p></span></p></td><td data-colwidth="93" width="277" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md7776961eey" style="font-size: 16px;" data-mpa-action-id="md77769r1ha8" data-pm-slice="0 0 []">&#34;c&#34;</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="145" width="277" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md776qaiajp" style="font-size: 16px;" data-mpa-action-id="md776qaz15" data-pm-slice="0 0 []">&#34;2WWSI&#34;</span><o:p></o:p></span></p></td><td data-colwidth="93" width="277" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md777a7d1m12" style="font-size: 16px;" data-mpa-action-id="md777a7nmsw" data-pm-slice="0 0 []">&#34;.&#34;</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;"><td data-colwidth="145" width="277" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md776mkabdt" style="font-size: 16px;" data-mpa-action-id="md776mktjuz" data-pm-slice="0 0 []">&#34;S%H}K63&#34;</span><o:p></o:p></span></p></td><td data-colwidth="93" width="277" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md777egx1euf" style="font-size: 16px;" data-mpa-action-id="md777ehe1dug" data-pm-slice="0 0 []">&#34;e&#34;</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:4;mso-yfti-lastrow:yes;"><td data-colwidth="145" width="277" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md776jr8sg3" style="font-size: 16px;" data-mpa-action-id="md776jruh42" data-pm-slice="0 0 []">&#34;D7MNTAS&#34;</span><o:p></o:p></span></p></td><td data-colwidth="93" width="277" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p><span lang="EN-US"><span leaf="" mpa-font-style="md777hqn8ad" style="font-size: 16px;" data-mpa-action-id="md777hrg21gf" data-pm-slice="0 0 []">&#34;u&#34;</span><o:p></o:p></span></p></td></tr></tbody></table>  
最终的脚本：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBnia2Pok8aSmGViaSzfs3ia9vciagWdcfoPBtjhMQCG3mqFiaQ6SWwrfKKFypQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
### 2.2 详细分析  
  
首先通过获取系统驱动器的序列号、计算器名，与随机字符串进行拼接用于生成唯一标识构造User-Agent。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBniatMtSn13GHjLfBLHIkWiaAicQDls8l8icjVzICtoo5oWwwf8XjXHSSo0xw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
尝试从HKEY_CURRENT_USER\Network\WindowsUpdates和HKEY_CURRENT_USER\Network\WindowsResponby中读取键值，优先使用WindowsUpdates键值，若长度不足，回退到WindowsResponby键值。若两者均无效，设置slideV1g标记加1。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBniaWWJAoM6DIIDPaAqgMUkGqLVy0qKKKv2aGe4nQMmVEyurL5QjpD1saw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
通过DNS查询服务解析destination.nushtosh.ru的IP地址，此处使用正则表达式提取响应中的IP地址，可绕过硬编码域名。与前期APT-C-53使用的手法相同，下载前依旧需要先对域名进行dns解析，然后将得到的ip拼接成URL。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBniaqB0tylMjC9PEB3GeHyPuCNiaztWb9W4fx4Vdd0fe3o1WexwyTwxFAwg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
使用自定义User-Agent发送HTTP GET请求，检查状态码是否为200或404，若状态码200时返回响应体。若状态码404时检查响应内容长度是否在28到120之间，如果符合，调用`EnglandCxd`写入注册表项。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PoHRzt4667a3MTVS6yweBniagwoautQftNpw6WcgU2STBvD0Tx9iaLXLic7QO72aDcYqNl5cR3QuGduA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
通过拼接后的URL下载并执行下一阶段的payload，通过这种方式，只要保持对域名的控制，APT-C-53可以不断更换远程服务器的地址，因此在类似攻击活动的检测和拦截中，除了http流量的目标地址以外，还需要关注DNS解析时的数据。  
  
使用MSXML解析Base64编码内容，解码后通过ExecuteGlobal执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4PqLibuGO9bug0HJF7jYQ7ekibJWyAEpKw0o1CUtVBXNYoc1chd6YBdvGJ4j2gkwUOGdYq58wcxz8Isw/640?wx_fmt=png&from=appmsg "")  
  
 三、归属研判   
  
360高级威胁研究院持续跟踪APT-C-53（Gamaredon）的相关攻击活动。上述分析仅展示了Gamaredon攻击活动的一部分，其相关攻击手段在以往的攻击行动中已有所展现。根据我们评估，Gamaredon很可能会继续针对乌克兰进行网络攻击，旨在获取敏感信息并破坏关键基础设施。我们也将持续监测和分析其新的攻击策略和手段。  
#  四、防范排查建议   
- 强化邮件安全防护：部署先进的邮件网关解决方案，过滤和拦截恶意附件和钓鱼邮件，特别是含有LNK文件和恶意压缩文件的邮件。  
  
- 加强系统和网络监控：实施全面的日志监控和分析，重点关注系统启动项、注册表修改以及PowerShell脚本的执行记录。  
  
- 强化终端安全防护：安装360安全卫士，并确保所有终端设备安装并定期更新反病毒和反恶意软件，进行全面的恶意软件扫描  
。  
  
#   
  
**附录 IOC**  
  
c1bcc107e436bbefc00c03cca31b8537  
  
84f9c71804aea33d51c7e724669214e6  
  
nushtosh[.]ru  
  
  
**团队介绍**  
  
  
TEAM INTRODUCTION  
  
**360****高级威胁研究院**  
  
360高级威胁研究院是360数字安全集团的核心能力支持部门，由360资深安全专家组成，专注于高级威胁的发现、防御、处置和研究，曾在全球范围内率先捕获双杀、双星、噩梦公式等多起业界知名的0day在野攻击，独家披露多个国家级APT组织的高级行动，赢得业内外的广泛认可，为360保障国家网络安全提供有力支撑。  
  
