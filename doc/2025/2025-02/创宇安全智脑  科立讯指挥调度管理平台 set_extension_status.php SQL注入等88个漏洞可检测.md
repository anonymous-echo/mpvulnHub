#  创宇安全智脑 | 科立讯指挥调度管理平台 set_extension_status.php SQL注入等88个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2025-02-20 09:20  
  
**创宇安全智脑**是基于知道创宇17年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件88个，其中重点插件9个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIGKHj4DQaAPG6oWdx3G34q2ic4PJ1psDicAw6dtqVZnFsToNAJITibL8dg/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、金盘移动图书馆系统 tabShow 信息泄露  
  
**发布时间：**2025-02-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
金盘移动图书馆系统是金盘软件为图书馆和阅读者提供便捷服务的软件系统。金盘移动图书馆系统 tabShow 接口存在信息泄露漏洞。未经授权的远程攻击者可以利用该漏洞，获取管理员账号密码。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，获取管理员账号密码。  
  
**建议解决方案：**  
  
及时更新至最新版本，实施严格的访问控制机制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="金盘移动图书馆系统" 对潜在可能目标进行搜索，共得到131条IP历史记录。主要分布在中国、美国。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLph5Hnm5jnp7vliqjlm77kuabppobns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIv90uTGYgfQY22iav84RZtq00aCKia9Mn5x6zLcoqJ7l5aBkmEjnglAOw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIuVL1cC3mLad9uqWpaibkHgRKFtwicK0Ge00trHM0mgE5sZarSDianpoog/640?wx_fmt=png&from=appmsg "")  
  
  
2、万户 ezOFFICE testFtpGet.jsp SQL注入  
  
**发布时间：**2025-02-17  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
万户 ezOFFICE 是北京万户软件技术有限公司推出的一款 OA 办公系统。万户 ezOFFICE testFtpGet.jsp 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="wanhu" 对潜在可能目标进行搜索，共得到793条IP历史记录。主要分布在中国、加拿大。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJ3YW5odSI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIEWSiban5f6pCicChuibJYeTnVu4D0PfhicoUZYpdOpUh0N8eLffwaMx9kQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboI2UR0caeLWWOMdT78M7vh8Vgc1yHKQfdpvJA2svquRr5FA9d4ib6UYjw/640?wx_fmt=png&from=appmsg "")  
  
  
3、万户 ezOFFICE testFtpPut.jsp SQL注入  
  
**发布时间：**  
2025-02-17  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
万户 ezOFFICE 是北京万户软件技术有限公司推出的一款 OA 办公系统。万户 ezOFFICE testFtpPut.jsp 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="wanhu" 对潜在可能目标进行搜索，共得到793条IP历史记录。主要分布在中国、加拿大。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJ3YW5odSI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIEWSiban5f6pCicChuibJYeTnVu4D0PfhicoUZYpdOpUh0N8eLffwaMx9kQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboI2UR0caeLWWOMdT78M7vh8Vgc1yHKQfdpvJA2svquRr5FA9d4ib6UYjw/640?wx_fmt=png&from=appmsg "")  
  
  
4、万户 ezOFFICE InfoTemplateEdit.jsp SQL注入  
  
**发布时间：**2025-02-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
万户 ezOFFICE 是北京万户软件技术有限公司推出的一款 OA 办公系统。万户 ezOFFICE InfoTemplateEdit.jsp 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="wanhu" 对潜在可能目标进行搜索，共得到793条IP历史记录。主要分布在中国、加拿大。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJ3YW5odSI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIEWSiban5f6pCicChuibJYeTnVu4D0PfhicoUZYpdOpUh0N8eLffwaMx9kQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboI2UR0caeLWWOMdT78M7vh8Vgc1yHKQfdpvJA2svquRr5FA9d4ib6UYjw/640?wx_fmt=png&from=appmsg "")  
  
  
5、天锐绿盾审批系统 sysadmin 信息泄露  
  
**发布时间：**2025-02-19  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
天锐绿盾审批系统是一套从源头上保障数据安全和使用安全的加密软件系统。天锐绿盾审批系统 sysadmin 接口存在信息泄露漏洞。未经授权的远程攻击者可以利用该漏洞，获取系统管理员账号密码等敏感信息。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，获取系统管理员账号密码等敏感信息。  
  
**建议解决方案：**  
  
及时更新至最新版本，实施严格的访问控制机制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="天锐绿盾审批系统" 对潜在可能目标进行搜索，共得到876条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLlpKnplJDnu7%2Fnm77lrqHmibnns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboI1c6yK7p5icyItrvZTFFjibSD4uUianTgUx5CgprnDf9vXAmO7Mc77XwyQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboI8zOto7TYAGfzFPlhqnI8e9Y24DmS3jVUCH0KRqBagtkfGT6oTcYCZQ/640?wx_fmt=png&from=appmsg "")  
  
  
6、红海云eHR achievementsStatistics.mob 远程代码执行  
  
**发布时间：**2025-02-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
红海云 eHR 是大中型企业广泛采用的人力资源管理系统。红海云eHR achievementsStatistics.mob 接口存在远程代码执行漏洞。恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用 Web 应用程序防火墙等安全工具来检测和阻止已知攻击模式，防止漏洞被利用。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="红海云eHR" 对潜在可能目标进行搜索，共得到238条IP历史记录。主要分布在中国广东、北京等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLnuqLmtbfkupFlSFIi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIgeicDLjxMBWAmp6bJE1bgx3fTeKoOkmBzDGGUKyxCat7EkmP7OwJnGQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIzYsBqBePFZvFHvXOS7aibgVvoCuJib1921fXSfeNl2Xt4rYHL45TnR4g/640?wx_fmt=png&from=appmsg "")  
  
  
7、金和 C6 协同管理平台 GetAdminData.aspx XML外部实体注入  
  
**发布时间：**2025-02-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
金和 OA 协同办公管理系统 C6 软件为用户提供一整套标准的办公自动化解决方案，以帮助企事业单位迅速建立便捷规范的办公环境。金和 C6 协同管理平台 GetAdminData.aspx 接口存在XML外部实体注入漏洞。恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，限制访问和过滤用户输入可帮助减少风险，建议在服务器配置中禁用外部实体解析以及合理设置应用程序或服务的权限，以防止XML外部实体注入漏洞。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="金和 C6 协同管理平台" 对潜在可能目标进行搜索，共得到618条IP历史记录。主要分布在中国北京、广东等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLph5HlkowgQzYg5Y2P5ZCM566h55CG5bmz5Y%2BwIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIpgt9c2UygF4nAg0wtjjtZAicPU0fuGTv3r2x2cKAlAnQ0gbhtGy5VIw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboINlnr9Vz7vyiceHytdFnAD8RBicFWyDn1gYA7X9poAYEdbfRlxEoXvX0w/640?wx_fmt=png&from=appmsg "")  
  
  
8、科立讯指挥调度管理平台 set_extension_status.php SQL注入  
  
**发布时间：**2025-02-14  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
科立讯指挥调度管理平台是一个针对通信行业的指挥调度管理平台。科立讯指挥调度管理平台 set_extension_status.php 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="科立讯指挥调度管理平台" 对潜在可能目标进行搜索，共得到707条IP历史记录。主要分布在中国、菲律宾等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLnp5Hnq4vorq%2FmjIfmjKXosIPluqbnrqHnkIblubPlj7Ai）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIQzgnb7pXic2SVIuxTibKuoD4lqD6ibr8y85XabmkicDIxvy3cA991Gjaog/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIjRF8Vs4V8k5CwTMoF824Hh9JnNAlUQsLq4sAHCgHXhKSj6a8vFXoWQ/640?wx_fmt=png&from=appmsg "")  
  
****  
9、Palo Alto Networks PAN-OS 管理端认证绕过（CVE-2025-0108）  
  
**发布时间：**2025-02-13  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-0108  
  
**漏洞描述：**  
  
Palo Alto Networks PAN-OS 是美国 Palo Alto Networks 公司的一套为其防火墙设备开发的操作系统。Palo Alto Networks PAN-OS 管理端存在认证绕过漏洞。未经授权的远程攻击者可以利用该漏洞绕过验证，读取系统敏感文件，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞绕过验证，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，防止认证机制失效，并对相关接口添加访问控制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Palo Alto Networks PAN-OS Firewall" 对潜在可能目标进行搜索，共得到3707条IP历史记录。主要分布在美国、印度等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJQYWxvIEFsdG8gTmV0d29ya3MgUEFOLU9TIEZpcmV3YWxsIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIyh1AlcYUjdib0BlHib9TJ07yp1nPnv8q0KZff2Dvx75k5VNoszYrHQibQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIc3HwDibyBcmNdlAdxhib3dfMySr9AgCX3HnrsESI3S37VJ9aDzIWjDJA/640?wx_fmt=png&from=appmsg "")  
  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yZmdf17K0Gwj1gJibQBgiboIfLXqDj241J3icpbSiamQ02Xx0DjzibCBtQ4WYFm2W9MV19uZp4wxibDnkg/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
