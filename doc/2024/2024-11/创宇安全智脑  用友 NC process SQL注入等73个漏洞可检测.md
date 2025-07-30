#  创宇安全智脑 | 用友 NC process SQL注入等73个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2024-11-28 09:31  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件73个，其中重点插件7个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa377QsDruaJvC5cyn3xpQ7W1Ixpgck1ytldNnAr2pUhBPBQZb5dL3UHTw/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、用友 U8 CRM getufvouchdata.php SQL注入  
  
**发布时间：**2024-11-25  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 U8 CRM 是用友公司推出的一款客户关系管理（CRM）软件，专为企业提供客户管理和服务支持。该软件旨在帮助企业建立和维护与客户之间的良好关系，提高客户满意度，增强销售和市场活动的效果。用友 U8 CRM getufvouchdata.php 接口 pID 参数存在SQL注入漏洞。未经授权的远程攻击者可以利用该漏洞非法获取数据库信息，造成敏感信息泄露。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="用友 U8 CRM" 对潜在可能目标进行搜索，共得到1141条IP历史记录。主要分布在中国、越南等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLnlKjlj4sgVTggQ1JNIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37BVLdAa3kC0LaYtaAKwibyrpQklEWycaDAft6UJwicFpZxNs7Oxq5rXpg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37H00YJwlMOaicPaDK7jTzXVwgjIFgwSep6uleRxAP50iaNbhhFvsiaQu8w/640?wx_fmt=png&from=appmsg "")  
  
  
2、用友 NC process SQL注入  
  
**发布时间：**2024-11-22  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 NC 是面向集团企业的世界级高端管理软件。用友 NC process 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Yonyou NC httpd" 对潜在可能目标进行搜索，共得到15243条IP历史记录。主要分布在中国、马来西亚等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJZb255b3UgTkMgaHR0cGQi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37BpeYKFK4YzxFJQLkwq34L4LRYMibvibZxOJGNfrr5hOcicTf8v3c9UVIQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37LIuPqfBQfnHibbZIuENnM1s1hTdUcvm1Dy8hbDiaMA73WHjwACrpMqbw/640?wx_fmt=png&from=appmsg "")  
  
  
3、海信智能公交企业管理系统 AdjustWorkHours.aspx SQL注入  
  
**发布时间：**  
2024-11-25  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
海信智能公交企业管理系统是由海信集团有限公司开发的一套智能化、数字化公交运营管理解决方案。该系统集成了公交调度、车辆监控、乘客服务、数据分析等功能，旨在帮助公交公司提升运营效率、优化调度管理、改善乘客体验，并实现智能化的企业管理。海信智能公交企业管理系统 AdjustWorkHours.aspx 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="海信智能公交企业管理系统" 对潜在可能目标进行搜索，共得到203条IP历史记录。主要分布在中国、日本等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLmtbfkv6Hmmbrog73lhazkuqTkvIHkuJrnrqHnkIbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37xpaGKBhCaKD2LqxfmKzaicAqhGjMYuxrS9ianBmNrGFSKV5cSSXmFbww/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37WqjdMwibbaj1UXPYq7ibhnZBgS108WXTibezRGYPbSiaUoKkjlklfS8elQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、SRM 智联云采系统 quickReceiptDetail SQL注入  
  
**发布时间：**2024-11-21  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
SRM 智联云采系统是由深圳智互联科技有限公司开发的一款供应链管理系统。SRM 智联云采系统 quickReceiptDetail 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="SRM 智联云采系统" 对潜在可能目标进行搜索，共得到2372条IP历史记录。主要分布在中国、俄罗斯等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJTUk0g5pm66IGU5LqR6YeH57O757ufIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa373DlNbCdsibWEeXhflrGofNic6zgVBJAOLldAI3cwlOHk4s9xSiaNEkwGA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa377gxbydVt0vRrf4RT3RRonE6ibYmO3ZPA0WIxPtt0LBf2eZnNQHpGR2A/640?wx_fmt=png&from=appmsg "")  
  
  
5、SRM 智联云采系统 receiptDetail SQL注入  
  
**发布时间：**2024-11-21  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
SRM 智联云采系统是由深圳智互联科技有限公司开发的一款供应链管理系统。SRM 智联云采系统 receiptDetail 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="SRM 智联云采系统" 对潜在可能目标进行搜索，共得到2372条IP历史记录。主要分布在中国、俄罗斯等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJTUk0g5pm66IGU5LqR6YeH57O757ufIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa373DlNbCdsibWEeXhflrGofNic6zgVBJAOLldAI3cwlOHk4s9xSiaNEkwGA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa377gxbydVt0vRrf4RT3RRonE6ibYmO3ZPA0WIxPtt0LBf2eZnNQHpGR2A/640?wx_fmt=png&from=appmsg "")  
  
  
6、SRM 智联云采系统 statusList SQL注入  
  
**发布时间：**2024-11-21  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
SRM 智联云采系统是由深圳智互联科技有限公司开发的一款供应链管理系统。SRM 智联云采系统 statusList 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="SRM 智联云采系统" 对潜在可能目标进行搜索，共得到2372条IP历史记录。主要分布在中国、俄罗斯等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJTUk0g5pm66IGU5LqR6YeH57O757ufIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa373DlNbCdsibWEeXhflrGofNic6zgVBJAOLldAI3cwlOHk4s9xSiaNEkwGA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa377gxbydVt0vRrf4RT3RRonE6ibYmO3ZPA0WIxPtt0LBf2eZnNQHpGR2A/640?wx_fmt=png&from=appmsg "")  
  
  
7、海信智能公交企业管理系统 apply.aspx SQL注入  
  
**发布时间：**2024-11-21  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
海信智能公交企业管理系统是由海信集团有限公司开发的一套智能化、数字化公交运营管理解决方案。该系统集成了公交调度、车辆监控、乘客服务、数据分析等功能，旨在帮助公交公司提升运营效率、优化调度管理、改善乘客体验，并实现智能化的企业管理。海信智能公交企业管理系统 apply.aspx 接口存在SQL注入漏洞。未经授权的远程攻击者可以利用该漏洞非法获取数据库信息，造成敏感信息泄露。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="海信智能公交企业管理系统" 对潜在可能目标进行搜索，共得到203条IP历史记录。主要分布在中国、日本等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLmtbfkv6Hmmbrog73lhazkuqTkvIHkuJrnrqHnkIbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37xpaGKBhCaKD2LqxfmKzaicAqhGjMYuxrS9ianBmNrGFSKV5cSSXmFbww/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37WqjdMwibbaj1UXPYq7ibhnZBgS108WXTibezRGYPbSiaUoKkjlklfS8elQ/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zHreaPS2EC62fjYR1FYa37iamoFVrV6OTTgQp7bQibF3JK7SmSB59m9OG5SORnKlU4koLCABcaCo3A/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
