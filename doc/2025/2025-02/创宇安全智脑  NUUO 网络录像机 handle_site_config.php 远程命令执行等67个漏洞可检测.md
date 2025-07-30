#  创宇安全智脑 | NUUO 网络录像机 handle_site_config.php 远程命令执行等67个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2025-02-27 09:10  
  
**创宇安全智脑**是基于知道创宇17年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件67个，其中重点插件7个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0t5WsibgFV06WO5n4IXZq3XChicKerrqdBUxSevWibiaajPSMNFP1ibslLeSA/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、Ivanti Endpoint Manager GetHashForWildcardRecursive 信息泄露（CVE-2024-13159）  
  
**发布时间：**2025-02-21  
  
**漏洞等级：**严重  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-13159  
  
**漏洞描述：**  
  
Ivanti Endpoint Manager（EPM）是由Ivanti公司开发的一款综合性端点管理解决方案，它帮助企业有效管理和保护网络中的端点设备，包括桌面、笔记本电脑、服务器、移动设备和虚拟环境等。2024 年 1 月 - 2025 年安全更新和 2022 SU6 1 月 - 2025 年安全更新之前的 Ivanti EPM GetHashForWildcardRecursive 端点由于通配符参数中的输入验证不当，允许攻击者指定触发 NTLM 身份验证的远程 UNC 路径，使得攻击者可强制获取 EPM 计算机帐户凭据，获取敏感信息。  
  
**漏洞危害：**  
  
攻击者可强制获取 EPM 计算机帐户凭据，获取敏感信息。  
  
**建议解决方案：**  
  
厂商已发布新版本修复该漏洞，请及时更新到最新安全版本。参考链接：  
  
https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6?language=en_US。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Ivanti EPM" 对潜在可能目标进行搜索，共得到73条IP历史记录。主要分布在美国、新加坡等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJJdmFudGkgRVBNIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tONyoJEArd6iarn0FdQ18j4WSscfUGhXGYKHvWqvYzXHRQIku13TrGug/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tGiaQnUSk1cCoiaibdSibxHsGEZhby9PficqObJbUphks2WcuHwWFCWx2ThA/640?wx_fmt=png&from=appmsg "")  
  
  
2、Ivanti Endpoint Manager GetHashForSingleFile 信息泄露（CVE-2024-13161）  
  
**发布时间：**2025-02-21  
  
**漏洞等级：**严重  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-13161  
  
**漏洞描述：**  
  
Ivanti Endpoint Manager（EPM）是由Ivanti公司开发的一款综合性端点管理解决方案，它帮助企业有效管理和保护网络中的端点设备，包括桌面、笔记本电脑、服务器、移动设备和虚拟环境等。2024 年 1 月 - 2025 年安全更新和 2022 SU6 1 月 - 2025 年安全更新之前的 Ivanti EPM GetHashForSingleFile 端点由于通配符参数中的输入验证不当，允许攻击者指定触发 NTLM 身份验证的远程 UNC 路径，使得攻击者可强制获取 EPM 计算机帐户凭据。  
  
**漏洞危害：**  
  
攻击者可强制获取 EPM 计算机帐户凭据，造成敏感信息泄露。  
  
**建议解决方案：**  
  
厂商已发布新版本修复该漏洞，请及时更新到最新安全版本。参考链接：  
  
https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6?language=en_US。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Ivanti EPM" 对潜在可能目标进行搜索，共得到73条IP历史记录。主要分布在美国、新加坡等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJJdmFudGkgRVBNIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tONyoJEArd6iarn0FdQ18j4WSscfUGhXGYKHvWqvYzXHRQIku13TrGug/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tGiaQnUSk1cCoiaibdSibxHsGEZhby9PficqObJbUphks2WcuHwWFCWx2ThA/640?wx_fmt=png&from=appmsg "")  
  
  
3、用友U8 Cloud pool.clearConnection.d XML外部实体注入  
  
**发布时间：**  
2025-02-21  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 U8 Cloud 是一款企业级 ERP，用于协助企业实现业务协同和流程管理的高效化和数字化。用友U8 Cloud pool.clearConnection.d 接口存在XML外部实体注入漏洞。恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，限制访问和过滤用户输入可帮助减少风险，建议在服务器配置中禁用外部实体解析以及合理设置应用程序或服务的权限，以防止XML外部实体注入漏洞。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="用友U8 Cloud" 对潜在可能目标进行搜索，共得到15593条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLnlKjlj4tVOCBDbG91ZCI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0t0cNlTHmQiajTGufgaxrYKRA9Qn2yYia427gzK8fIA3W5m52qAAJs5e4Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tH933ObOtRyrID0w9NRlW7iaASWkxXg2mIwichGUoD7ow8aWKyKxZic5jg/640?wx_fmt=png&from=appmsg "")  
  
  
4、天问物业ERP AjaxUpload.aspx 任意文件上传  
  
**发布时间：**2025-02-20  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
天问物业云是一款由成都天问互联开发的物业集成管理平台。天问物业ERP AjaxUpload.aspx 接口存在任意文件上传漏洞。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="天问物业ERP" 对潜在可能目标进行搜索，共得到140条IP历史记录。主要分布在中国广东、北京等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLlpKnpl67niankuJpFUlAi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0t1gum2KC42pHQNu75pyL95KjuOD1QNRCmQLlQ8hz4pvx8oF5bG0tcgQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tlq1X0KE8xN90r6Bkrkj4MncaaNibAtrp6Tqa0zIibNEhSrJtfT1HDrOQ/640?wx_fmt=png&from=appmsg "")  
  
  
5、万户 ezOFFICE BookMarkEditFrm.jsp SQL注入  
  
**发布时间：**2025-02-20  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
万户 ezOFFICE 是北京万户软件技术有限公司推出的一款 OA 办公系统。万户 ezOFFICE BookmarkEditFrm.jsp 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="wanhu" 对潜在可能目标进行搜索，共得到793条IP历史记录。主要分布在中国、加拿大。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJ3YW5odSI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0ty6UrQGQnG115hwjsaRsdLh6oGNGzSSTvCKjvRX1LqfFOvj0wElB6icg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tUic16nglWphwbqIDNqLP8N7lnlUpkpk4E5ggSyLVD4RHXrwALNc5TGQ/640?wx_fmt=png&from=appmsg "")  
  
  
6、NUUO 网络录像机 handle_site_config.php 远程命令执行  
  
**发布时间：**2025-02-20  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
NUUO 网络录像机是中国台湾省 NUUO 公司推出的一款 NVR 设备，该设备主要用于管理IP摄像头，并通过互联网进行实时监控和录像存储。NUUO 网络录像机 handle_site_config.php 接口存在远程命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="NUUO 网络录像机" 对潜在可能目标进行搜索，共得到47898条IP历史记录。主要分布在德国、日本等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJOVVVPIOe9kee7nOW9leWDj%2BacuiI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tuzldLZkNJW6CneNjuozUicIgL40eLm7D0ojY03jjj0yxYWYibC1SQZbQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0tYqwNQNePjibeXPzJefnc89O2VnaPlGkBePibpUf3vLnNcib7jq4XciaBzw/640?wx_fmt=png&from=appmsg "")  
  
  
7、天问物业ERP controller.ashx 任意文件上传  
  
**发布时间：**2025-02-20  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
天问物业云是一款由成都天问互联开发的物业集成管理平台。天问物业ERP controller.ashx 接口存在任意文件上传漏洞，该漏洞源于 UEditor 组件的 catchimage 功能，可下载远程恶意文件至服务器。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="天问物业ERP" 对潜在可能目标进行搜索，共得到140条IP历史记录。主要分布在中国广东、北京等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLlpKnpl67niankuJpFUlAi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0ticpZgH07VtpQskAZx2wckRVpzFFUF68fdb7xl79HApMsqbltKBhrl3Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0t3DTvib3VU83D1QrZyiawRleLerjUW6ibjBN7AgteNuKQphOtTupGt3CJA/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xjPmaQ5sIbdvibIaZAKgF0ts46RxmJpgxEKrKO3rfkjBmJ084T0FfbcJkEfQLjKzr14yrh1nPiapmA/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
