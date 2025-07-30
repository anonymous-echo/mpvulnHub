#  【实战攻防纪实】“NGSOC+N”联动出击，7分钟扼杀危急漏洞利用攻击   
 奇安信集团   2024-09-25 17:49  
  
【引言】  
     
  
2024国家级攻防演练已告一段落。在此次趋于常态化的超长演练时间内，传统的断网、关停端口等临时措施已不再适用于防守企业的防御策略，而是更注重构建常态化的安全防御机制。在这一过程中，单一的安全产品已不足以快速应对更加复杂的威胁。因此  
，  
打破安全设备孤岛，促进设备间的协同工作与统一管理，让安全运营过程更简单、更智能，  
成为企业在演练中必须面对的课题。  
  
恰逢2024攻防演练期间，奇安信对  
安全攻防BU和安全运营BU进行整合，正式成立安全运营BG  
。这一变革使得公司能够在实战攻防对抗中，  
从客户的安全运营需求出发，  
重新评估产品间的协同合作；同时也推动客户突破了各自为战的传统安全设备使用模式，  
全方位体验安全运营BG旗下各产品的联动优势  
，从而显著  
提升整体安全运营效率，真正实现“以快制胜”  
。  
  
在这一过程中，客户最为经典的联动方式之一就是  
“NGSOC+N”  
的组合，即  
NGSOC与天眼、QAX-GPT安全机器人、SOAR  
之间的协同作业。具体部署方式如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9wGKwYNlY92t2Iw9C4Lqob0aZmla0FKEhmjvfs4MIic3A5kAwjvERHBA/640?wx_fmt=png "")  
  
1、  
NGSOC+天眼（监测）：  
NGSOC作为安全人员  
集中的威胁监测及运营平台  
，接收来自包括  
天眼在内  
的多种安全设备的告警信息。通过最新版本中的  
“智能分诊”告警降噪功能  
，将原本需要  
数小时  
才能完成的告警筛选过程  
压缩到秒级  
，从而在海量告警中迅速识别出  
可能对关键资产造成严重影响的1%重要告警信息  
。      
  
2、  
NGSOC+QAX-GPT安全机器人（分析）：  
通过接口与NGSOC相连的安全机器人，不仅能对  
上述“智能分诊”初步过滤的告警进行“确诊”，进一步筛选出攻击成功的“有效告警”  
，实现高效的  
“双重告警降噪”，消除高达90%的告警噪声  
；还能辅助安全分析师进行  
智能化的事件研判  
，将原本需要  
多名专家花费数小时  
的工作量，  
减少到由初级人员在几分钟甚至几秒钟内  
即可完成  
复杂事件  
的分析。  
  
3、  
NGSOC+SOAR（处置）  
：  
通过  
预设的SOAR剧本  
与NGSOC的对接，实现了  
处置流程的自动化  
，避免了人工干预导致的响应延迟，将原本需要  
几天或几小时  
的响应时间  
缩短至几分钟甚至几秒钟之内  
。  
  
这种“NGSOC+N”的联动机制，不仅显著缩短了从威胁监测、研判到处置的闭环时间，大幅提升了安全运营效率，还彻底解放了安全人员的双手，使多平台间的协作变得更加高效、便捷。更重要的是，它极大地增强了企业在面对网络安全威胁时的整体防御能力，使企业在应对频繁且复杂的攻击时更具反击力。  
  
  
**案例概览：**  
  
**五大利器实现“7分钟”奇迹**  
    
  
今天，让我们一起看看某金融客户在实战攻防演习中，如何巧妙地通过  
NGSOC平台，联动天眼、QAX-GPT安全机器人、SOAR、加特林  
这四大利器，仅用  
7分钟  
便完成了从发现攻击者企图攻击，到研判确认攻击成功，并详尽追踪攻击手法，同时使用SOAR自动化剧本在  
秒级时间内  
一键隔离攻击源、阻断攻击链、扫描隐患资产。      
            
  
注：案例内容采写于客户现场的奇安信驻场安服人员小杨（化名）。  
            
  
告警监测：  
小杨在NGSOC平台进行告警监测时，通过使用NGSOC平台上的“智能分诊”功能及调用GPT机器人接口实现  
“双重告警降噪”，消除了90%的告警噪声  
，使小杨能够在攻击者企图攻击的  
1分钟内  
发现由天眼系统捕获上传的  
危急  
“润乾报表系统dataSphereServlet任意文件上传漏洞”告警。  
     
  
研判分析：  
尽管经验尚浅，小杨并不需要求助于高级专家，借助GPT机器人的智能研判，在  
2分钟  
内便完成了详细的攻击过程和取证信息分析，包括  
关联取证与文件解码  
。  
  
响应处置：  
小杨一键执行NGSOC内的告警处置剧本，将处置指令发送至  
SOAR系统  
，自动联动  
防火墙封禁  
NGSOC系统中  
所有  
与润乾报表系统漏洞相关的告警中的  
攻击者IP，并自动触发加特林系统  
扫描重点资产中是否存在该漏洞。处置结果在  
1秒  
内同步至NGSOC，小杨的蓝信也收到通知。  
            
  
**案例详情：**  
  
**“NGSOC+N”的全程联动纪实**  
   
   
  
1、告警发现  
  
2024年7月23日上午11点15分  
，小杨在NGSOC监测界面上发现多条由  
天眼系统  
捕获并标记为“危急”的告警，告警名称名均为“润乾报表系统dataSphereServlet任意文件上传漏洞”。而且这些告警均源来自同一IP地址，在11点14分至11点15分期间对该客户系统发起了多轮攻击尝试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn95TfXeIf6QofibzNfvJtbABGicZEcWicoKrz5dkY33NRtFMia12FaPaBicLA/640?wx_fmt=png "")  
  
尽管小杨能在  
攻击发生后的1分钟内  
就注意到这些可疑告警信息，但在面对NGSOC内多设备来源的海量告警数据时，仅凭借一双眼睛显然是不够的。实际上，这一切的背后离不开NGSOC新功能“智能分诊”与QAX-GPT安全机器人的“双重降噪”机制。  
  
首先，  
NGSOC新版中的“智能分诊”功能  
为告警进行了  
首轮降噪  
。在过去，从海量告警中筛选出重要信息需要多名同事分工协作，而现在，只需在NGSOC界面上一键点击“重点关注告警”按钮，小杨就能够迅速定位到那些  
针对关键资产且可能引发严重后果的告警信息  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9wQQNNNH2GTftorxnpT4vkkUXdUp8WEnGQyM39icBdhf0q4IfXyd3cYg/640?wx_fmt=png "")  
  
NGSOC“智能分诊”首轮告警降噪  
        
  
接着，  
在NGSOC系统内调用QAX-GPT安全机器人的接口，进行“二次”告警降噪  
。小杨在上述NGSOC“智能分诊”后的列表中点击“QAX-GPT研判状态”按钮，这些已被初步降噪的告警信息被QAX-GPT安全机器人再次过滤，准确地区分出攻击成功的“有效告警”和未攻击成功的“无效告警”。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9z0saCJ6Mxuq4GQdJW4pyaqtw35zGAqlU6If8DJTuibUGugbfPiaRWeYQ/640?wx_fmt=png "")  
  
图：GPT安全机器人二次降噪  
            
  
通过“智能分诊”的初步降噪与QAX-GPT的二次确认，在一个NGSOC系统内有效地消除了90%的告警噪声。正是这种高效的“双重降噪”机制，使得小杨能够在攻击发生后的1分钟内，迅速捕捉到“润乾报表dataSphereServlet任意文件上传漏洞”这一紧急告警。  
            
  
2、告警研判  
  
11点16分  
，小杨立即着手对“润乾报表dataSphereServlet任意文件上传漏洞”告警进行深入分析。  
  
以往研判类似复杂的危急告警时，小杨通常需要寻求资深专家的帮助，但现在，只需要在NGSOC页面一键启动QAX-GPT安全机器人，就能获得专业的智能研判。  
  
瞬息之间，QAX-GPT便提供了一份详细的分析说明：  
攻击者利用润乾报表系统任意文件上传漏洞，上传了可执行脚本文件monitor.jsp，响应码为200，响应体中包含了一段JavaScript代码，以及文件保存路径为/monitor.jsp，因此判断攻击成功。  
  
为了进一步确认攻击者上传的monitor.jsp文件是否真的成功，小杨在GPT对话框内输入了查询请求：“请关联查询这个monitor.jsp的web访问记录。”随即，GPT机器人自动触发了  
关联取证分析  
，确认该文件确实已被成功访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9rCdhyqWbHlxbgEAQic4FRuZRI5e9KksSN6icgOvSBQEUSXO7nSao2QIA/640?wx_fmt=png "")  
  
紧接着，为了了解上传文件的内容，小杨又向GPT机器人发送了  
解码指令  
。从解码数据中可以看出，文件内容还经过一次Unicode编码。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9ib3Oiau8KSMaKbchElzX61LJW6z4iabz7fuEjcdKUQrNuCyXuN5TSicyBg/640?wx_fmt=png "")  
  
从上述GPT解码结果，以及综合研判内容看，基本可以确定攻击者上传的monitor.jsp是一个恶意文件。  
  
3、响应处置  
            
  
11点18分，  
依据上述GPT安全机器人给出的详细研判结论，小杨立即联系应急响应组进行上机排查，清除该monitor.jsp恶意文件。  
  
与此同时，小杨立即在NGSOC中的该条告警下，  
右键点击“联动处置”  
，一键联动防火墙封禁该攻击IP地址。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9sVWwiamovqXnicNPkVAqfO2rJBaNs3ZvDeticfCJqVHL9eEeSG3ic9PNgw/640?wx_fmt=png "")  
  
图：在NGSOC内一键联动防火墙封禁IP  
  
4、切断隐患  
  
为了进一步排查除了本次安全事件告警中涉及的攻击者IP外，是否有其他攻击者同样利用了润乾报表漏洞进行攻击，并及时封禁这些潜在攻击者的IP地址，小杨立即对本条告警发生  
前两个小时内的告警记录  
展开详细排查。  
       
  
在告警排查中，不同于以往需在NGSOC平台逐一按条件搜索并手动封禁攻击者IP的繁琐流程，如今，小杨只需在NGSOC平台上本条告警之下  
一键执行预先配置好的SOAR“剧本”  
。这一操作使得针对该漏洞利用的  
“告警排查指令”  
能够即时自动发送至奇安信SOAR系统，并在  
毫秒内  
检索出  
近2个小时内NGSOC平台上所有与润乾报表漏洞相关的告警信息  
，随即  
自动联动防火墙封禁  
这些告警中涉及的  
所有攻击者IP地址  
。  
            
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9Rt0QDR1KnlApPapYZPRJmPsx42yzU0zuB0bxMDv57zibu9fXqLMNzJA/640?wx_fmt=png "")  
  
图：在NGSOC内一键联动SOAR执行处置剧本  
            
  
与此同时，当在NGSOC上执行上述SOAR剧本时，关于该漏洞的  
“漏洞扫描指令”  
也将同步自动发送至奇安信SOAR系统，并  
自动触发奇安信加特林系统  
对企业的  
全部内网资产进行全面扫描  
，检查公司内网资产中  
是否同样存在此类漏洞  
，从而彻底切断攻击者利用该润乾报表系统漏洞实施任何攻击的可能性。  
       
       
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn97CezCGjoLDDvicxEkHrMP7UMPzM5ksEAkQR8YfibibSyeAXlfAXpML6iaA/640?wx_fmt=jpeg "")  
  
图：SOAR系统中关于漏洞处置的剧本  
  
最终，SOAR在  
短短1秒内  
便变完成了  
“告警排查指令”与“漏洞扫描指令”的执行，处理结果  
同步反馈至NGSOC平台，自动更新告警处置状态，并通过“蓝信”窗口实时通知了小杨。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/G3LNmiaOGjaqPBytRrwia2cTibJ3zECRKn9ibwUnjfOzrhkyaX4OGNE7nSKUOXGLoEicIzZFIR3gomMzeibOTA6miaaDQ/640?wx_fmt=png "")  
  
图：SOAR通过蓝信实时发送事件处置完毕的通知  
            
  
可以看到，  
上述NGSOC与SOAR联动处置的过程一气呵成，一系列操作无需人工干预，1秒内全部自动完成。  
这种自动化快速响应的方式，  
尤其适合深夜时段、无人值守的场景  
，可以最大程度缩短威胁响应时间，有效遏制威胁扩散。  
            
  
11点18分10秒  
，根据加特林漏洞扫描结果，小杨进一步对资产采取了必要的加固措施，确保系统的安全性。  
  
11点22分，  
应急响应组反馈，已完成对相关业务目录的检查，并发现了上传的monitor.jsp文件，随即立即清除了该文件。  
  
至此，关于“润乾报表系统dataSphereServlet任意文件上传漏洞”的事件已在短短7分钟内完成闭环处置。  
  
接下来，我们还将发布一系列攻防演练故事，分享客户如何借助安全运营BG旗下各类产品和服务，构建起无缝协作、协同联动的防御体系，提升安全运营效率，解放安全人员的双手。敬请关注！      
  
  
