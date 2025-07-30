> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&mid=2247581146&idx=1&sn=1830583e37a926c2a4f087da7557e73d

#  360勒索预警：广大政企机构警惕！Weaxor勒索病毒盯上OA办公系统  
 360数字安全   2025-07-04 09:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/pLEuriaaPnU362NhLdPIDibrhibC5gfZR980tl5kIv8p6m64VHJU1n0pa7WajQ3lticuSKic1icw7xGRNGibTiaibdI7g7Q/640?wx_fmt=gif "")  
  
近期，360安全智能体监测数据显示，Weaxor勒索软件攻击呈爆发式增长态势，近一个月内接收相关案例超百例，占比国内勒索病毒传播量一半以上。该家族后缀为.wxx，实为Mallox勒索软件迭代版本，自2024年10月现身国内后，2025年已长期占据本土勒索攻击榜首。  
  
  
当前，勒索软件攻击愈发复杂和精密，多采用多阶段复合攻击链，结合数据库漏洞利用、无文件攻击等技术，实现持久化渗透，Weaxor攻击案例的激增正印证了这一趋势。  
  
  
  
  
**借用主流OA系统实施入侵**  
  
**显著提升攻击成功率与隐蔽性**  
  
  
360数字安全集团捕获的一起样本案例显示，其攻击载荷设计尤为典型。攻击者将恶意代码拆解为防御规避模块与ShellCode解码模块构成的双重架构，通过载荷间的协同作业，显著提高了攻击的成功率和隐蔽性。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqt0ytNG7Y5Diaq25tLTlibgVcGMeqtw6jgb5DWkq7c1ibJ72wGf14MiboXxg/640?wx_fmt=png&from=appmsg "")  
  
  
值得注意的是，本轮国内攻击中，利用主流OA系统实施入侵已成常态。在360捕获的样本案例中，攻击者正是通过某企业OA系统突破内网防线，构建起包含漏洞利用、权限维持、勒索部署的完整攻击链。这种将业务系统作为跳板的技术路径，使攻击更具迷惑性和破坏力。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtTaxjRzH6PtRG8ULCYglFYHvsyxhvCI0UUiarG5dEdLz2cPibKMhHAiakA/640?wx_fmt=png&from=appmsg "")  
  
针对OA系统的入侵进程链  
  
  
攻击者入侵成功后即刻执行PowerShell命令，下载伪装为"beta"文件的混淆型PowerShell脚本。360经多轮逆向分析解密发现，该脚本实为第一阶段内存载荷。该恶意载荷通过HTTP协议与黑客部署的C2服务器建立隐蔽信道后，实现数据窃取与Weaxor勒索软件下发。  
  
  
对这一段载荷的ShellCode代码进行功能解析，发现其会进行如下四个步骤的工作。首阶段在内存中动态地查找并获取所需的Windows API函数地址，利用wininet.dll库的功能连接到硬编码的C2服务器，模拟浏览器请求伪装成JS文件的加密shellcode，并在内存中直接注入执行；次阶段载荷经多层解密后，最终在受害者设备内存空间释放经过混淆处理的PE文件，完成"渗透-驻留-勒索"的完整攻击闭环。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtgV48h1K6sAn8Svxtvlfr6IOXqmVoCcAZlzv6BGx34mPR4DJA1IlqGg/640?wx_fmt=png&from=appmsg "")  
  
投放Weaxor勒索软件  
  
  
360在进一步对被释放出的样本进行分析，发现其启动后首先会进行一些准备工作，如更改电源方案为高性能模式，以加快加密速度，同步还会实施系统提权操作。  
  
  
此外，其还会自动识别并终止针对俄语、白俄罗斯语、乌克兰语、土库曼语、哈萨克语等俄语区设备的攻击链；执行防御规避阶段删除关键注册表项与卷影副本，彻底破坏系统恢复能力；最终在加密前还会通过POST的方法将一些用户信息发送到自己的C2服务器上，以便进行数据统计。  
  
  
在完成环境适配后，Weaxor勒索软件首先排除系统关键目录和特定扩展名文件，避免重复加密损耗性能。在加密过程中，其加密引擎采用双重加密机制，先使用ChaCha20流密码加密文件数据，再通过AES算法对ChaCha20的密钥进行加密保护。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtJUyq08hGkIAMXXQOZicDWv67jH9dIaSCrWRiaTM4gPMV0yQ84pic8ygxg/640?wx_fmt=png&from=appmsg "")  
  
加/解密系统构架  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtft7qBLsc0ibpjmK8FbibQib0ibcGiby6JA8V1Gl3voLWMt9mQEBOOkQF1VA/640?wx_fmt=png&from=appmsg "")  
  
数据与密钥流向图  
  
  
加密的最后阶段，勒索软件会向文件数据尾部追加加密标识符，防止自身被二次运行导致重复加密，最终被加密的文件均会被添加.wxx后缀。  
  
  
在完成文件加密后，Weaxor勒索软件会在所有受感染目录中植入名为FILE RECOVERY.txt的勒索信，向受害者索要相当于8000至14000元人民币的虚拟货币赎金，且第三方数据恢复商常在此价格基础上加收手续费。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtA4keRnIVia2BOzlhfCic0n4YhYRSfVRTSKLgjIttOfibEZsvafkZGbD3A/640?wx_fmt=png&from=appmsg "")  
  
  
但强烈建议广大政企机构拒绝支付，因为未修复的系统漏洞和安全隐患将使设备持续暴露于风险之中，即使支付赎金恢复数据，也极可能遭遇二次加密甚至多次反复攻击，形成恶性循环。  
  
  
**360打造体系化解决方案**  
  
**构建全流程勒索防护能力**  
  
  
作为数字安全的领导者，360数字安全集团多年来一直致力于勒索病毒的防范。基于过去20年积累的安全大数据、实战对抗经验，以及全球顶级安全专家团队等优势能力，360推出基于安全大模型赋能的勒索病毒防护解决方案，能够针对勒索病毒从攻击前、攻击中到攻击后的每一个主要节点进行定向查杀，实现多方位、全流程、体系化、智能化的勒索防护。  
  
  
  
  
针对Weaxor勒索病毒攻击，360勒索病毒防护解决方案打造了多项定制化的防护功能。  
  
在初始入侵阶段，通过Web服务防护与黑客入侵拦截模块能够有效阻断勒索软件投毒路径；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtDUrEO3yZZUtZBlSDJvEGsBM2W9o0p8PcIgbZK6s5FjPLLqpuF86N4w/640?wx_fmt=png&from=appmsg "")  
  
  
面对攻防对抗环节，核晶防护引擎与高级威胁检测技术可实时识别并阻断黑客组织的渗透攻击行为；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtC5UNdMBAtoQewwe4Thp3fZ3aO17SF0NQQXBVIveEn9Lp4EaM7SRJzQ/640?wx_fmt=png&from=appmsg "")  
  
  
针对核心数据威胁，智能文档防护模块对异常加密操作实施精准拦截；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtiaR2weDmHDoR5mjuEILhGRmVTdc51HWaEqxQjnldiczribXA77iah4clfA/640?wx_fmt=png&from=appmsg "")  
  
  
即使发生入侵事件，渗透痕迹检测功能仍可为未安装终端提供事后溯源支持，形成“入口防御-攻防对抗-核心保护-事后溯源”的多层级防御闭环。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU25QkQwwibXic3SUJMbP1KDqtOYRVX9s302iaM2a3LZWbtziboja6Kt9yIOsepcnlQ982M7gNDsjBiczyA/640?wx_fmt=png&from=appmsg "")  
  
  
目前，360勒索病毒防护解决方案已经实现对该类勒索病毒的全面查杀&解密。同时，针对不同类别的勒索病毒，该方案还根据不同客户体量与需求推出了多元产品及服务套餐，已累计为超万例勒索病毒救援求助提供帮助。  
  
  
  
**如需咨询相关服务**  
  
**请联系电话**  
  
**400-0309-360**  
  
  
  
  
往期推荐  
  
<table><tbody><tr><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table><tbody><tr><td rowspan="2" data-colwidth="25.0000%" width="25.0000%" style="border-color: rgb(62, 62, 62);border-style: none;background-repeat: no-repeat;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_jpg/pLEuriaaPnU1xlwDZic75Rl5UglbRXA2lJFo2tJbpC0O8Mn86O07M9MlFQjHJdM8gq6KUIua0v4wD9b9PRjjuapg/640?wx_fmt=jpeg&amp;from=appmsg&#34;);padding: 0px;background-position: 30.0133% 0% !important;background-size: 171.545% !important;"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;text-align: left;"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 24px;line-height: 1;"><p style="text-align: left;"><strong><span leaf="">01</span></strong></p></section></section></td><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;"><section style="color: rgb(140, 140, 140);line-height: 1;font-size: 14px;"><p style=""><span style="color: rgb(145, 196, 110);"><span leaf="">● </span></span><span style="color: rgb(58, 66, 94);"><span leaf="">央视报道：360锁定台民进党当局“资通电军”黑客组织首要嫌犯</span></span></p></section></section></td></tr><tr><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-bottom: 5px;"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;"><span style="color: rgb(208, 208, 208);"><span leaf="">► <a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247580720&amp;idx=1&amp;sn=548311a4a4093c6cdcdc23e8db3cace7&amp;scene=21#wechat_redirect" textvalue="点击阅读" data-itemshowtype="0" linktype="text" data-linktype="2">点击阅读</a></span></span></p></section></section></td></tr></tbody></table></section></section></td></tr><tr><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table><tbody><tr><td rowspan="2" data-colwidth="25.0000%" width="25.0000%" style="border-color: rgb(62, 62, 62);border-style: none;background-repeat: no-repeat;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU1xlwDZic75Rl5UglbRXA2lJtV0WkwbjOMsMTIocEmHK81ToDBbX000ODef4qhrB4t9TIicH48RbSyw/640?wx_fmt=png&amp;from=appmsg&#34;);padding: 0px;background-position: 63.5676% 0% !important;background-size: 139.503% !important;"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 24px;line-height: 1;"><p style="text-align: left;"><strong><span leaf="">02</span></strong></p></section></section></td><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;"><section style="color: rgb(140, 140, 140);line-height: 1;font-size: 14px;"><p style=""><span style="color: rgb(145, 196, 110);"><span leaf="">● </span></span><span style="color: rgb(58, 66, 94);"><span leaf="">权威首选：360安全大模型一体机引领行业场景落地</span></span></p></section></section></td></tr><tr><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-bottom: 5px;"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;"><span style="color: rgb(208, 208, 208);"><span leaf="">► <a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247580882&amp;idx=1&amp;sn=aaa6b0e850f9a95766aeae3bc322b149&amp;scene=21#wechat_redirect" textvalue="点击阅读" data-itemshowtype="0" linktype="text" data-linktype="2">点击阅读</a></span></span></p></section></section></td></tr></tbody></table></section></section></td></tr><tr><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table><tbody><tr><td rowspan="2" data-colwidth="25.0000%" width="25.0000%" style="border-color: rgb(62, 62, 62);border-style: none;background-repeat: no-repeat;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU1xlwDZic75Rl5UglbRXA2lJFF6lSr3udcxRvFCzBRKcUmjSe1745tCQoyNeGtnAIQg5taudCeibXGg/640?wx_fmt=png&amp;from=appmsg&#34;);padding: 0px;background-position: 18.8832% 0% !important;background-size: 172.324% !important;"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 24px;line-height: 1;"><p style="text-align: left;"><strong><span leaf="">03</span></strong></p></section></section></td><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;"><section style="color: rgb(140, 140, 140);line-height: 1;font-size: 14px;"><p style=""><span style="color: rgb(145, 196, 110);"><span leaf="">●</span></span><span style="color: rgb(202, 29, 24);"></span><span style="color: rgb(58, 66, 94);"><span leaf="">“实战王牌”360 EDR，又双叒来秀操作啦！</span></span></p></section></section></td></tr><tr><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-bottom: 5px;"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;"><span style="color: rgb(208, 208, 208);"><span leaf="">► <a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247580806&amp;idx=1&amp;sn=ca9c1cc008b983c94a138d3bdc2a1f6f&amp;scene=21#wechat_redirect" textvalue="点击阅读" data-itemshowtype="0" linktype="text" data-linktype="2">点击阅读</a></span></span></p></section></section></td></tr></tbody></table></section></section></td></tr><tr><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(62, 62, 62) rgb(255, 255, 255);border-style: none;padding: 0px 0px 10px;"><section style="min-height: 40px;margin-right: 0%;margin-left: 0%;"><section style="width: 100%;margin-right: auto;margin-bottom: -10px;margin-left: auto;"><table><tbody><tr><td rowspan="2" data-colwidth="25.0000%" width="25.0000%" style="border-color: rgb(62, 62, 62);border-style: none;background-repeat: no-repeat;background-attachment: scroll;vertical-align: bottom;background-image: url(&#34;https://mmbiz.qpic.cn/sz_mmbiz_png/pLEuriaaPnU1xlwDZic75Rl5UglbRXA2lJs4GF9pkL6JdzUj946hZcVO9nedfBbBMOPaAPvGOjtVn4jynEoaepVA/640?wx_fmt=png&amp;from=appmsg&#34;);padding: 0px;background-position: 100% 0% !important;background-size: 105.256% !important;"><section style="margin-right: 0%;margin-bottom: 4px;margin-left: 0%;"><section style="text-align: right;padding-right: 4px;padding-left: 4px;color: rgb(255, 255, 255);font-size: 24px;line-height: 1;"><p style="text-align: left;"><strong><span leaf="">04</span></strong></p></section></section></td><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-top: 10px;margin-right: 0%;margin-left: 0%;"><section style="color: rgb(140, 140, 140);line-height: 1;font-size: 14px;"><p style=""><span style="color: rgb(145, 196, 110);"><span leaf="">● </span></span><span style="color: rgb(58, 66, 94);"><span leaf="">360携手广西赋能东盟数字经济发展 深化数字安全与智能创新</span></span></p></section></section></td></tr><tr><td data-colwidth="75.0000%" width="75.0000%" style="border-color: rgb(62, 62, 62);border-style: none;padding-top: 0px;padding-bottom: 0px;background-color: rgb(249, 249, 249);"><section style="margin-bottom: 5px;"><section style="line-height: 1;color: rgb(140, 140, 140);font-size: 12px;"><p style="text-align: right;"><span style="color: rgb(208, 208, 208);"><span leaf="">► <a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247580710&amp;idx=1&amp;sn=67c6a0627dfb0ec45b4ec2cd68143656&amp;scene=21#wechat_redirect" textvalue="点击阅读" data-itemshowtype="0" linktype="text" data-linktype="2">点击阅读</a></span></span></p></section></section></td></tr></tbody></table></section></section></td></tr></tbody></table>  
  
  
