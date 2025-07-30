#  创宇安全智脑 | 大华 DSS 数字监控系统 adminOperate 信息泄露等79个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2024-12-05 09:47  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件79个，其中重点插件8个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh7iaLp9jSPLpthBLML5WkjFQibiaDgjPibSIRGDKia3lwRIUqP6jbYTWl9oA/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、紫光档案管理系统 uploadScan SQL注入  
  
**发布时间：**2024-12-04  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
紫光档案管理系统是专为企事业单位提供档案信息化解决方案的管理系统。紫光档案管理系统 uploadScan 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="紫光档案管理系统" 对潜在可能目标进行搜索，共得到284条IP历史记录。主要分布在中国、英国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLntKvlhYnmoaPmoYjnrqHnkIbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh7QnFict3AFs3gQaXs75gVMppzfNg5xjtlyqdlIpa9fQeYSXXEwe4fYQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhbTNyYcYkLL4tfcibL6xDyCJUW0O2tmpEB3yc3micanZROvVia9ia5hp6gg/640?wx_fmt=png&from=appmsg "")  
  
  
2、Jeecg-Boot 企业级快速开发平台 getTotalData SQL注入（CVE-2024-48307）  
  
**发布时间：**2024-12-04  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-48307  
  
**漏洞描述：**  
  
Jeecg-Boot 是 JeecgBoot 社区的一款基于代码生成器的低代码平台。Jeecg-Boot 企业级快速开发平台存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Jeecg-Boot 企业级快速开发平台" 对潜在可能目标进行搜索，共得到13281条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJKZWVjZy1Cb290IOS8geS4mue6p%2BW%2Fq%2BmAn%2BW8gOWPkeW5s%2BWPsCI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhDdvmWgKTtfbWNxGUoicf3AicASj8oruoJX0jImLM0xvdfXIgAJiblL4YQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhJYG1IqXxWtYUIsebYemGx3Yc81JHIQBG9w1TMTIfo1WUwg0VWVUn6w/640?wx_fmt=png&from=appmsg "")  
  
  
  
3、大华 DSS 数字监控系统 adminOperate 信息泄露  
  
**发布时间：**  
2024-12-03  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
大华 DSS 数字监控系统是浙江大华技术股份有限公司开发的一款安防视频监控系统。大华 DSS 数字监控系统 adminOperate 接口存在信息泄露漏洞。未经授权的远程攻击者可以利用该漏洞，获取ftpUser、ftpPassword等敏感信息。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，获取ftpUser、ftpPassword等敏感信息。  
  
**建议解决方案：**  
  
及时更新至最新版本，实施严格的访问控制机制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="大华 DSS 数字监控系统" 对潜在可能目标进行搜索，共得到3933条IP历史记录。主要分布在中国、智利等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLlpKfljY4gRFNTIOaVsOWtl%2BebkeaOp%2Bezu%2Be7nyI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh5lHicjCMvgdficErmoXQ7cAvwbzibjIprhibpdEjZe5FQAkkvmDpaLIqQQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhcHB81ib1c9CNibqKWZYouTEHeiaeeDxpQbdcseX3kJ7NJicRIMJe09F1nA/640?wx_fmt=png&from=appmsg "")  
  
  
4、昂捷 ERP cwsfiledown.asmx 任意文件读取  
  
**发布时间：**2024-12-02  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
昂捷 ERP 管理系统是深圳市昂捷信息技术股份有限公司开发的一款企业管理软件，为企业提供了一整套管理及资源规划解决方案。昂捷 ERP cwsfiledown.asmx 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="昂捷 ERP" 对潜在可能目标进行搜索，共得到1247条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLmmILmjbcgRVJQIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh0GjqgjibWXKno9LR9vicfuaLycLnqEgh1FMwNePMHfp0j4xsdgqzxgkw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dht5u7Gric1iaYZ9l6SrOsHOE4z09gaJY7O0DV0AgJvKT809OINibrez3yg/640?wx_fmt=png&from=appmsg "")  
  
  
5、顺景ERP管理系统 GetFile 任意文件读取  
  
**发布时间：**2024-12-02  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
顺景ERP管理系统是由顺景软件科技有限公司研发的一款企业资源规划（ERP）系统，专注于为制造业企业提供全面的信息化解决方案。顺景ERP管理系统 GetFile 接口存在任意文件读取漏洞，未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="顺景 ERP" 对潜在可能目标进行搜索，共得到581条IP历史记录。主要分布在中国、越南等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLpobrmma8gRVJQIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dhd8rncmrZQHwCkTGEhgicR9Oia6Dqs1EVYqfuDKvX36r57RyOAzibAOISQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh0GNwoPzt8qIF8vvMSZs7iaDelzicVpGjWbd5ibf8mbTntgRR3GA6uaBFg/640?wx_fmt=png&from=appmsg "")  
  
  
6、用友NC nc.itf.ses.DataPowerService XML实体注入  
  
**发布时间：**2024-12-02  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
用友NC是面向集团企业的世界级高端管理软件。用友NC nc.itf.ses.DataPowerService 接口存在XML实体注入漏洞。恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞导致服务器端请求伪造（SSRF）和敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，限制访问和过滤用户输入可帮助减少风险，建议在服务器配置中禁用外部实体解析以及合理设置应用程序或服务的权限，以防止XML外部实体注入漏洞。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Yonyou NC httpd" 对潜在可能目标进行搜索，共得到15243条IP历史记录。主要分布在中国、马来西亚等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJZb255b3UgTkMgaHR0cGQi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhLQxbq6HVKryv2EXe1ic1FiaPT8z0xJD3IJcyU8129B7COwz10OSdhviag/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh6722W17YB6J1A2tFFMQjVF1rPb6nqK20pmZ2Vk0ou7bMI0SZRoyrZg/640?wx_fmt=png&from=appmsg "")  
  
  
7、湖南建研工程检测系统 PreviewB_Source.cshtml 任意文件读取  
  
**发布时间：**2024-12-02  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
湖南建研工程检测系统是一款由湖南建研信息技术有限公司开发的一款工程管理软件。湖南建研工程检测系统 PreviewB_Source.cshtml 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="湖南建研工程检测系统" 对潜在可能目标进行搜索，共得到553条IP历史记录。主要分布在中国湖南、广西等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLmuZbljZflu7rnoJTlt6XnqIvmo4DmtYvns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh5qbFXrKg8XlLe1YE8rO8e6A9kZIUlzVeFAgytvYpI0rwOZA7oZtqXw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh4amiajEtjIqTOCEFB1jSUjo8xcdHKkgRib1jM59MS8ppV5QaxLUicaOFA/640?wx_fmt=png&from=appmsg "")  
  
****  
8、Sitecore Experience Platform 未授权任意文件读取（CVE-2024-46938）  
  
**发布时间：**2024-11-29  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
Sitecore Experience Platform（Sitecore XP）‌是一个全面的数字体验管理（DXM）平台，旨在帮助企业在所有数字渠道上创建、管理和提供个性化、引人入胜的全渠道体验。Sitecore Experience Platform 存在未授权的任意文件读取漏洞。恶意攻击者可通过漏洞读取web.config等文件，结合利用.NET ViewState 反序列化即可实现远程代码执行，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
官方已发布补丁修复该漏洞，请及时升级到最新安全版本。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Sitecore Experience Platform" 对潜在可能目标进行搜索，共得到2855条IP历史记录。主要分布在美国、荷兰等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSJTaXRlY29yZSBFeHBlcmllbmNlIFBsYXRmb3JtIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhH95RWvrcMBN2YwQPwVtKwI4ebBibCzx1x4MUTQnKdscTcs4nvJZdy2w/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8DhTmibxBAQjDpFNkmfrdeQvtTDIm6EiaRpu9YJajaVZj5smgibae99XrOvg/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0zGdYIHrGFP4FMILTw0m8Dh7DVyA6zlPX3sIGsibAA8icRg6qulIpzOIzzsNos6Ul5ALL1dYibdsMfeQ/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
