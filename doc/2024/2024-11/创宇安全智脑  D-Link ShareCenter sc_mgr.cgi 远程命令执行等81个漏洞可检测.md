#  创宇安全智脑 | D-Link ShareCenter sc_mgr.cgi 远程命令执行等81个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2024-11-21 09:18  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件81个，其中重点插件8个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK35dwPCwHugax2daGy9iaic3aPjeQyTLtibNH0nzuYHOngDBSOxP0137RMA/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、D-Link ShareCenter sc_mgr.cgi 远程命令执行  
  
**发布时间：**2024-11-15  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
D-Link ShareCenter 是 D-Link 公司推出的一系列网络存储设备 (NAS) 产品系列。D-Link ShareCenter sc_mgr.cgi 接口存在远程命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="D-Link ShareCenter" 对潜在可能目标进行搜索，共得到302962条IP历史记录。主要分布在英国、法国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJELUxpbmsgU2hhcmVDZW50ZXIi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3Capfd0v7Sib0vCpwInzMgqN6X0lnSbWBiaZVz5YEuGTTx7egyJ8CYvSw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3OnHH8whNtEjk1R2AxePVpItWGwESDCdHicSCkyyiaGCicbribTRN9wQxBA/640?wx_fmt=png&from=appmsg "")  
  
  
2、浙大恩特客户资源管理系统 CompInfoAction.emrser SQL 注入  
  
**发布时间：**2024-11-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
浙大恩特客户资源管理系统是恩特软件开发的一款客户资源管理系统。浙大恩特客户资源管理系统 CompInfoAction.emrser 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="浙大恩特客户资源管理系统" 对潜在可能目标进行搜索，共得到1050条IP历史记录。主要分布在中国、美国。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLmtZnlpKfmgannibnlrqLmiLfotYTmupDnrqHnkIbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3weKJegQjSozj08UiafNIabhric0ibZcqSmbSlet8T4hnmTd4gly7ibNrnQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3OxzClmowdhtkkQR8PNAA7doCwWj7VCApT2VxicHaNgTb1ZrR9pdFIqg/640?wx_fmt=png&from=appmsg "")  
  
  
3、Altenergy电力系统控制软件 status_zigbee SQL注入（CVE-2024-11305）  
  
**发布时间：**  
2024-11-19  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-11305  
  
**漏洞描述：**  
  
Altenergy电力系统控制软件是一款由Altenergy电力系统公司开发的微型逆变器控制软件。Altenergy电力系统控制软件 status_zigbee 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Altenergy电力系统控制软件" 对潜在可能目标进行搜索，共得到511条IP历史记录。主要分布在法国、加拿大等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJBbHRlbmVyZ3nnlLXlipvns7vnu5%2FmjqfliLbova%2Fku7Yi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3KSO8cwkgVVObjicfej1zicOGd2SeeutGULu0B1HgkDjNHGOaATia1oPBQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3snFHv9JibIS9ztd5Ot2q3SWC9KmXticJeByxn1NSa3kQQmDsds1O36Cw/640?wx_fmt=png&from=appmsg "")  
  
  
4、东胜物流软件 CertUpload 任意文件上传  
  
**发布时间：**2024-11-19  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
东胜物流软件是一款致力于为客户提供 IT 支撑的 SOP。东胜物流软件 CertUpload 接口存在任意文件上传漏洞。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。****  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="东胜物流软件" 对潜在可能目标进行搜索，共得到947条IP历史记录。主要分布在中国、德国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLkuJzog5znianmtYHova%2Fku7Yi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3OYpIKns1JCPWyWLQEXdEhHTgupliaj3uwNqt51VOQYSDWnHcT0XaZsQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3mmtrcUDTHiacvuJPAIuq9qzvdEMRjfc1OsofXamc1dBV1ZbPpdGCKhg/640?wx_fmt=png&from=appmsg "")  
  
  
5、SRM 智联云采系统 getSuppliers SQL注入  
  
**发布时间：**2024-11-19  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
SRM 智联云采系统是由深圳智互联科技有限公司开发的一款供应链管理系统。SRM 智联云采系统 getSuppliers 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="SRM 智联云采系统" 对潜在可能目标进行搜索，共得到2370条IP历史记录。主要分布在中国、俄罗斯等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJTUk0g5pm66IGU5LqR6YeH57O757ufIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3k7Vl6W1J0AjShCvuMuEIyu3VutEKjic0jqcru9gge71qiczxGV80l8ibw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK32Nuib71FCnlqyL1ibvqmQy8DwlRcKeGiaicPGp1MJOpDEG3uOEQaSiarDYg/640?wx_fmt=png&from=appmsg "")  
  
  
6、任我行CRM Edit SQL注入  
  
**发布时间：**2024-11-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
任我行CRM是一款集OA自动化办公、OM目标管理、KM知识管理、HR人力资源为一体集成的企业管理软件。任我行CRM Edit 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="任我行CRM" 对潜在可能目标进行搜索，共得到972条IP历史记录。主要分布在中国江苏、浙江等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLku7vmiJHooYxDUk0i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3UJNgRblzXFzz9Lz6WMuCIwzM71lTwH1E8DK9e6atoKLGv6jFvL10EA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3tMFzUxbyFUl0F8uRc5u1e2uN8arSYV70vFaZofeLsQYaOA3WwU3JBA/640?wx_fmt=png&from=appmsg "")  
  
  
7、顺景ERP管理系统 UploadInvtSpBuzPlanFile 任意文件上传  
  
**发布时间：**2024-11-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
顺景ERP管理系统是由顺景软件科技有限公司研发的一款企业资源规划（ERP）系统，专注于为制造业企业提供全面的信息化解决方案。顺景ERP管理系统 UploadInvtSpBuzPlanFile 接口存在任意文件上传漏洞。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="顺景 ERP" 对潜在可能目标进行搜索，共得到580条IP历史记录。主要分布在中国、越南等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLpobrmma8gRVJQIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK39YKFgr6lZJF54IoHNgNN07LBSUdgPsu3eQicOmDeSVNFicCgCOSaKvwg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3bx5pZR0XT3viaWD5rvTyY2Ev66ToftSza7fUH9oIS5ia7CtzsPtA2svA/640?wx_fmt=png&from=appmsg "")  
  
****  
8、大商创多用户商城系统 wholesale_flow.php SQL注入  
  
**发布时间：**2024-11-19  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
大商创多用户商城系统是一款支持自营和招商入入驻的 B2B2C 多用户商城系统。大商创多用户商城系统 wholesale_flow.php 接口存在SQL注入漏洞。攻击者可以利用该漏洞执行未授权的数据库命令，从而访问、窃取、修改或删除数据库中存储的敏感数据。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="大商创多用户商城系统" 对潜在可能目标进行搜索，共得到2680条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLlpKfllYbliJvlpJrnlKjmiLfllYbln47ns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3FQYGibxsqcicVv1vHvzTARB8gh7cibSgyveV7LicyicIvLmLIBBWtJgmic4Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3c3kibwc9tAApSnPAaKksWVf9BnDTZEJTwyk9gWG7YdDpHub566xesnw/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0ysZ0aIh6stoLOQTxrVGAK3icAxgAA9GiacWbF4NicicKL7ubt4O7ZSsXEp8eQZMJLBXyXDxic6icX9qjibg/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
