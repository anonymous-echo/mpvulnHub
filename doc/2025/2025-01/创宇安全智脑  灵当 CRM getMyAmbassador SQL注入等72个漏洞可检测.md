#  创宇安全智脑 | 灵当 CRM getMyAmbassador SQL注入等72个漏洞可检测   
创宇安全智脑  创宇安全智脑   2025-01-02 09:56  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件72个，其中重点插件6个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE66euJGeOTCVw1VIkDFTb3JXKp7JqtR30CVVCvJibjlbBXICy1iba64I5g/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、Cleo 文件传输软件 Synchronization 任意文件读取（CVE-2024-50623）  
  
**发布时间：**2024-12-23  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50623  
  
**漏洞描述：**  
  
Cleo 文件传输软件是一款企业级的数据传输和集成解决方案，主要用于帮助企业在供应链、财务、客户关系等领域高效地进行数据交换和系统集成。Cleo 文件传输软件 Synchronization 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Cleo 文件传输软件" 对潜在可能目标进行搜索，共得到553860条IP历史记录。主要分布在美国、日本等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJDbGVvIOaWh%2BS7tuS8oOi%2Bk%2Bi9r%2BS7tiI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6T5uhBO7ouFmcH5k3YX1SDRunickichjFJlvdVh0uT3KKNBzeYQxjQAibQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6iaBRu2ZibNPicyO3P2MhVPiagqSfViaDa97Rh23iaCvZT5VcqsFC9SBwJfCQ/640?wx_fmt=png&from=appmsg "")  
  
  
2、快云服务器助手 GetDetail 任意文件读取  
  
**发布时间：**2024-12-30  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
快云服务器助手是一款由快云信息科技有限公司开发的免费服务器管理工具。快云服务器助手 GetDetail 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="快云服务器助手" 对潜在可能目标进行搜索，共得到370条IP历史记录。主要分布在中国、印度尼西亚等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLlv6vkupHmnI3liqHlmajliqnmiYsi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6zu72BWJWaZAxe76Uf2w4HOoOYSbsZamqBQLDGBa4xnhyZRtmA0Ao1Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6ZxdXR4lm2TZiczSt3WicibIib6yxhDxPO6hvvXmju8FzF8e0EAZevabxIw/640?wx_fmt=png&from=appmsg "")  
  
  
3、赛诸葛数字化智能中台系统 login SQL注入  
  
**发布时间：**  
2024-12-26  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
赛诸葛企业数字化中台为企业级客户提供数智化转型升级的软件产品，帮助企业实现推广、销售到服务、管理全链条打通形成一体化闭环式服务，帮助传统企业逐步实现数字化转型升级。赛诸葛数字化智能中台系统 login 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="赛诸葛数字化智能中台系统" 对潜在可能目标进行搜索，共得到1399条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLotZvor7jokZvmlbDlrZfljJbmmbrog73kuK3lj7Dns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6r8xiafH45uOV11VSA1ScAHN2De4DYCIO0aQCbeqIpntcOuYm0nfjHgg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6BFTicwyYgjZvicCxt4aQNXTUZiaUIxChQwjyRSrACgSbR2QzpWMuOIpIA/640?wx_fmt=png&from=appmsg "")  
  
  
4、博斯外贸管理软件 loginednew.jsp SQL注入  
  
**发布时间：**2024-12-25  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
博斯外贸管理软件是由杭州博斯软件开发有限公司开发的一款专注于外贸行业的管理软件。博斯外贸管理软件 loginednew.jsp 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="博斯外贸管理软件" 对潜在可能目标进行搜索，共得到271条IP历史记录。主要分布在中国浙江、山东等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLljZrmlq%2FlpJbotLjnrqHnkIbova%2Fku7Yi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6icLVpM7HLzZCoZFZDvCCq8zA1wgdMSiaIBIibLIzt4yYc3m8FBcSNktfg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE60lOkAEQTkCBZCptKfO1bRdJzGK8Luf5FbLk2OaoQvbpejFPQkwPyQQ/640?wx_fmt=png&from=appmsg "")  
  
  
5、灵当 CRM getMyAmbassador SQL注入  
  
**发布时间：**2024-12-25  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
灵当 CRM 是一款由上海灵当信息科技有限公司开发的客户关系管理软件。灵当 CRM getMyAmbassador 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="灵当 CRM" 对潜在可能目标进行搜索，共得到4784条IP历史记录。主要分布在中国、新加坡等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLngbXlvZMgQ1JNIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6fZFObpTNI5zhJdxVUZJSYOnkkpagyicl0Nfv7C8mMVCxTQ3rr3RF6kg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6db2Zqia3rFGnYHfwFCvELQJp1uCcTnwAg1hAb7XnsXVVPt9HU1fYnUg/640?wx_fmt=png&from=appmsg "")  
  
  
6、博斯外贸管理软件 logined.jsp SQL注入  
  
**发布时间：**2024-12-26  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
博斯外贸管理软件是由杭州博斯软件开发有限公司开发的一款专注于外贸行业的管理软件。博斯外贸管理软件 logined.jsp 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="博斯外贸管理软件" 对潜在可能目标进行搜索，共得到271条IP历史记录。主要分布在浙江、山东等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLljZrmlq%2FlpJbotLjnrqHnkIbova%2Fku7Yi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6icLVpM7HLzZCoZFZDvCCq8zA1wgdMSiaIBIibLIzt4yYc3m8FBcSNktfg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE60lOkAEQTkCBZCptKfO1bRdJzGK8Luf5FbLk2OaoQvbpejFPQkwPyQQ/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yuOnKZ6JQzlf1aKuebBGE6Ulun1icp7Psqf1GWsfydvq9OpUnydzERMia46sKPAoUrhmPRvd3TeEuw/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
