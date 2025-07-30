#  创宇安全智脑 | Optilink upgrade.php 远程命令执行等61个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2025-04-17 08:05  
  
**创宇安全智脑**  
是基于知道创宇17年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件61个，其中重点插件6个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacuDdNH6gfMibfZTzrFicONs2EmtUA7LOF5krGnxCgd7QAI0zH2dvsvaGg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞详情  
  
  
**新增插件：**  
  
  
1、Optilink upgrade.php 远程命令执行  
  
**发布时间：**  
2025-04-14  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
Optilink 是一款光纤管理平台。Optilink upgrade.php 接口存在系统命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Optilink" 对潜在可能目标进行搜索，共得到8056条IP历史记录。主要分布在巴西、孟加拉等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Optilink%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacOhfOM7eVtU6e4VEbLUaDEvstOicz3YkicNgtn7CiajXo5kXyuI3q6GiaNQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiac4vpFyZyXbhvSIwDiawa5vrEejAiadLc7GZesAQyBe0S4nm2491YqRHwQ/640?wx_fmt=png&from=appmsg "")  
  
  
2、金和 C6 协同管理平台 ImportGuide2Xml.aspx XML 外部实体注入  
  
**发布时间：**  
2025-04-15  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
金和 OA 协同办公管理系统 C6 软件为用户提供一整套标准的办公自动化解决方案，以帮助企事业单位迅速建立便捷规范的办公环境。金和 C6 协同管理平台 ImportGuide2Xml.aspx 接口存在XML外部实体注入漏洞。恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，限制访问和过滤用户输入可帮助减少风险，建议在服务器配置中禁用外部实体解析以及合理设置应用程序或服务的权限，以防止XML外部实体注入漏洞。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="金和 C6 协同管理平台" 对潜在可能目标进行搜索，共得到604条IP历史记录。主要分布在中国北京、山东等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E9%87%91%E5%92%8C%20C6%20%E5%8D%8F%E5%90%8C%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiachYlHftCFCyFJrhYjslrXibEhkjoibQtyzvpHtKj0pmg20nzbYtgPg9cw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiac7vTmicYvjDXxiaBAicov6qNNseKWsnf4r0fVlmm4TF7gDwZxzIfHiaYy8g/640?wx_fmt=png&from=appmsg "")  
  
  
3、NetMizer 日志管理系统 hostipreport.php 远程命令执行  
  
**发布时间：**  
2025-04-15  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
NetMizer 日志管理系统是一种用于管理和监控计算机网络活动和日志的软件系统。NetMizer 日志管理系统 hostipreport.php 接口存在远程命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="NetMizer 日志管理系统" 对潜在可能目标进行搜索，共得到470条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22NetMizer%20%E6%97%A5%E5%BF%97%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiac0HHvicX7XYM25UHu71ibkU8OEJiaNXnKdRTZQVcggolGO91J7LHFkLU8A/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiaceBNtJicIg9FLnaYMVQRWw1IUjceOvsAjkpNKo6YdgaR1tJkcIW9avcg/640?wx_fmt=png&from=appmsg "")  
  
  
4、Elestio Memos 服务端请求伪造（CVE-2025-22952）  
  
**发布时间：**  
2025-04-14  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-22952  
  
**漏洞描述：**  
  
Elestio Memos 是一款轻量级、自托管的开源备忘录平台。Elestio Memos 0.23.0 版本存在服务端请求伪造漏洞，攻击者可利用该漏洞发起网络请求，攻击内网设备。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞探测内网信息，攻击内网主机。  
  
**建议解决方案：**  
  
官方已发布新版本修复该漏洞，请及时升级到最新版本。参考链接：  
  
https://github.com/usememos/memos/releases  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Elestio Memos" 对潜在可能目标进行搜索，共得到3990条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Elestio%20Memos%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacQYOyIVNMfba9t2qRgNb6Amq0bEKUiatiaWTsttc85caBQIPbwfjBLiaKQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacytN2uJLqYoLGqmnXFblg28LwicYt6r88GzLRpC7GFRX4EuHsv7cjYTQ/640?wx_fmt=png&from=appmsg "")  
  
  
5、  
哪吒监控面板默认口令  
  
**发布时间：**  
2025-04-11  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
哪吒监控面板是一款自托管、轻量级的服务器和网站监控和运维工具。哪吒监控面板存在默认口令漏洞。未修改默认密码的情况下，攻击者可以利用默认口令登录系统，使用管理员权限执行敏感操作。  
  
**漏洞危害：**  
  
未修改默认密码的情况下，攻击者可以利用默认口令登录系统，获取系统敏感信息。  
  
**建议解决方案：**  
  
及时更改默认口令，使用字母大小写、数字、特殊符号的8位以上复杂密码。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="哪吒监控面板" 对潜在可能目标进行搜索，共得到5508条IP历史记录。主要分布在美国、中国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E5%93%AA%E5%90%92%E7%9B%91%E6%8E%A7%E9%9D%A2%E6%9D%BF%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacckrBgWianuIWwCG50MD5hSWQEfuOU50geOYYKDNYibiaMbf1ZRSuyLiaibQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiac2FbfEjOaCduAgtJdagqvwhXntrj2NrQpArVhq662PnyyicQt0icSxO3w/640?wx_fmt=png&from=appmsg "")  
  
  
6、同鑫T9eHR信息化管理系统 disconnect SQL注入  
  
**发布时间：**  
2025-04-10  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
同鑫 T9eHR 信息化管理系统是一款专业的人力资源管理平台。同鑫T9eHR信息化管理系统 disconnect 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="同鑫T9eHR信息化管理系统" 对潜在可能目标进行搜索，共得到615条IP历史记录。主要分布在中国、越南等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E5%90%8C%E9%91%ABT9eHR%E4%BF%A1%E6%81%AF%E5%8C%96%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiac20eVCh3caPHwjFzsC3y2OiaGD0jCMa2nWHKs2zEMyWWhGwBsgYL0a5w/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacDRtsUJicI3qqqVFmO6RCh553gaOGocOD9h4Av7hs5UdG0Jh3DLkrGXw/640?wx_fmt=png&from=appmsg "")  
  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**  
，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wtdlX8mA2bziceiadcicvkoiacJCdtzLOjHnQeJhnhSmS0wdM5OibVsFs6auibSJImy9udpOGW4rTqQPbg/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
