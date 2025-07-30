#  创宇安全智脑 | 小皮面板 JWT 硬编码认证绕过等71个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2025-04-30 07:50  
  
**创宇安全智脑**  
是基于知道创宇17年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
2025年04月23日至2025年04月29日累计更新漏洞插件71个，其中重点插件9个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONrheb7t6IiaZTKTMnoswaw1VHJEib3GibGgiaUhOayO0KwRd9mSiabZhxuMA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞详情  
  
  
**新增插件：**  
  
  
1、Browser Use WebUI pickle 反序列化远程代码执行  
  
**发布时间：**  
2025-04-27  
  
**漏洞等级：**  
严重  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
Browser Use WebUI 是一种基于浏览器的自动化工具，能够帮助用户通过图形界面（GUI）轻松实现网页操作的自动化。Browser Use WebUI 在1.7版本以前由于使用 pickle 加载配置文件，存在反序列化漏洞。攻击者可通过该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
厂商已发布补丁修复该漏洞，请及时更新到最新安全版本。参考链接：  
  
https://github.com/browser-use/web-ui/releases/tag/v1.7。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Browser Use WebUI" 对潜在可能目标进行搜索，共得到124条IP历史记录。主要分布在美国、中国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Browser%20Use%20WebUI%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONicFtzmibiaY5icnFThibzlehHeoHgJLcVLycd39hdjy6mWZib1mLS6Mnju3A/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONJdFGCkgTnUic7JRvEqD803KFTHAsfZV6PsUvKPFos2bVq4lQgibDokJA/640?wx_fmt=png&from=appmsg "")  
  
  
2、Commvault 控制中心服务端请求伪造致远程代码执行（CVE-2025-34028）  
  
**发布时间：**  
2025-04-28  
  
**漏洞等级：**  
严重  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-34028  
  
**漏洞描述：**  
  
Commvault 控制中心是 CommVault Systems 的一部分，它是一个全面的备份和恢复解决方案，旨在帮助企业管理和保护其数据。Commvault 控制中心 deployWebpackage.do 接口存在未经认证的服务端请求伪造漏洞，恶意攻击者可通过该漏洞上传恶意 ZIP 文件，当目标服务器解压这些文件时，会导致远程代码执行。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
厂商已发布新版本修复该漏洞，请及时更新到最新安全版本。参考链接：  
  
https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Commvault 控制中心" 对潜在可能目标进行搜索，共得到3148条IP历史记录。主要分布在美国、印度等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Commvault%20%E6%8E%A7%E5%88%B6%E4%B8%AD%E5%BF%83%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONwYUAEmLvV9tpoT0ILNY7MDYIibkZuhuGTGCCJBNqNicyUlCbBfh7DRjg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONOjHhhLGjKq4EyeLahiaARVxpPPNIpLH6tfP2kDW7Uvl6w4UmSdJFibibw/640?wx_fmt=png&from=appmsg "")  
  
  
3、小皮面板 JWT 硬编码认证绕过  
  
**发布时间：**  
2025-04-27  
  
**漏洞等级：**  
严重  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
小皮面板（XPanel）是由河南小皮安全技术有限公司开发的服务器管理面板，前身是2007年发布的phpStudy，并于2024年基于新技术架构重构升级。小皮面板使用硬编码的默认 JWT 密钥，攻击者可以使用这个默认密钥生成有效的 JWT token，从而绕过认证执行未经授权的操作，如执行任意命令获取系统权限。  
  
**漏洞危害：**  
  
攻击者可以使用这个默认密钥生成有效的 JWT token，从而绕过认证执行未经授权的操作，执行任意命令获取系统权限。  
  
**建议解决方案：**  
  
厂商暂未发布新版本修复该漏洞，受影响的用户可临时修改'/xp/panel/config.json'中的jwt signingKey值为随机强密钥，并通过运行xp命令重启面板以修复漏洞。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="小皮面板" 对潜在可能目标进行搜索，共得到390条IP历史记录。主要分布在美国、中国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E5%B0%8F%E7%9A%AE%E9%9D%A2%E6%9D%BF%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONYC1L8FC4NdiaUrJ9INMRJYm0Hynh9RXjopiboibz6vstbd0WpYyzMSFTw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONB2ViayOVaNbUbqwb3O4Qdbn2cEtqLQgwicOD9HFiauvK2jibiabRn0UVSKQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、金蝶云星空 DataCenterService 远程代码执行  
  
**发布时间：**  
2025-04-28  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
金蝶云星空结合当今先进管理理论和数十万家国内客户最佳应用实践，面向事业部制、多地点、多工厂等运营协同与管控型企业及集团公司，提供一个通用的 ERP 服务平台。金蝶云星空 DataCenterService 接口存在远程代码执行漏洞。恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用 Web 应用程序防火墙等安全工具来检测和阻止已知攻击模式，防止漏洞被利用。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="金蝶云星空" 对潜在可能目标进行搜索，共得到8347条IP历史记录。主要分布在中国、新加坡等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E9%87%91%E8%9D%B6%E4%BA%91%E6%98%9F%E7%A9%BA%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONzmu471ZkrE574y3DQxyuMmc4zrHdc8boibVz0eMquY1Nic7n6mGugddw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONv3Z3Ys8RibpszjzticZw19ZGfQzfSfKRn5jqJBHEDNq7ibOAd38SGZCTA/640?wx_fmt=png&from=appmsg "")  
  
  
5、  
广联达 Linkworks IconAdd.ashx 任意文件读取  
  
**发布时间：**  
2025-04-27  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
广联达 Linkworks 是一种用于协同办公和项目管理的软件工具。广联达 Linkworks IconAdd.ashx 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="广联达 Linkworks" 对潜在可能目标进行搜索，共得到5533条IP历史记录。主要分布在中国、巴基斯坦等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E5%B9%BF%E8%81%94%E8%BE%BE%20Linkworks%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONlgicOmOfNZl7Pic2jLxLQI3AeQnpKhVCv7ZT5GibAgo0mXSuOZIWJ6rFg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONAW3icE3GxD4Bb7v2qg5SvrkOgyX56M7AkklicCpxEPxujVpf2X5hwqRA/640?wx_fmt=png&from=appmsg "")  
  
  
6、CentreStack 反序列化远程代码执行（CVE-2025-30406）  
  
**发布时间：**  
2025-04-24  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-30406  
  
**漏洞描述：**  
  
CentreStack 是 Gladinet 旗下的一款云服务协作平台。CentreStack 16.4.10315.56368 以下版本由于在 IIS web.config 文件中硬编码 machineKey 导致 ASP.NET ViewState 反序列化远程代码执行。未经授权的远程攻击者可以利用该漏洞以 IISAPPPOOLportaluser 身份执行任意代码，接管系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
厂家已修复漏洞，请及时更新至最新版本或手动修改 web.config 中的 machineKey。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="CentreStack" 对潜在可能目标进行搜索，共得到1393条IP历史记录。主要分布在美国、澳大利亚等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22CentreStack%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONa28biaXYYNZZXn4NfFoUz7tYJPNnaIM4qsr1ZeAkbLc0ic4yeo9Hb3MA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONKyaiawibPy2dC2CiatqaMUNDZZjH9K6S6ag69Q87wo1084jK6ZJ5kcpKw/640?wx_fmt=png&from=appmsg "")  
  
  
7、金和 C6 协同管理平台 Upload.ashx 任意文件上传  
  
**发布时间：**  
2025-04-27  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
金和 OA 协同办公管理系统 C6 软件为用户提供一整套标准的办公自动化解决方案，以帮助企事业单位迅速建立便捷规范的办公环境。金和 C6 协同管理平台 Upload.ashx 接口存在任意文件上传漏洞。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="金和 C6 协同管理平台" 对潜在可能目标进行搜索，共得到604条IP历史记录。主要分布在中国北京、山东等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E9%87%91%E5%92%8C%20C6%20%E5%8D%8F%E5%90%8C%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONaMeuVptLVDDNm94EKia3ULyhYHStG0ycdJSF9y0vEWY7l3BEktUSlhA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONEA0dLQNrCejUib6AI3SibY7lg00sLhG4WncZbwuibnxc7yiczodZwXL1Nw/640?wx_fmt=png&from=appmsg "")  
  
  
8、海康威视 iVMS 综合安防管理平台 getPic 任意文件读取  
  
**发布时间：**  
2025-04-24  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
海康威视iVMS综合安防系统是以安全防范业务应用为导向，以视频图像应用为基础手段，综合视频监控、联网报警、智能分析、运维管理等多种安全防范应用系统，构建的多业务应用综合管理平台。海康威视iVMS综合安防系统 getPic 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="海康威视 IVMS" 对潜在可能目标进行搜索，共得到66289条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E6%B5%B7%E5%BA%B7%E5%A8%81%E8%A7%86%20IVMS%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONxHF4kwDaZzex2c9ia6esnsDeiahdZXytuibv2yDM8w9JuvWz9xfccYMlg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONXTFCMSRdy5gml9f6fibSD0tf9eiaTfAgfXAMuRhRq09I8WW5fwHDkZJg/640?wx_fmt=png&from=appmsg "")  
  
  
9、思迅商旗 QueryBackendLog SQL注入  
  
**发布时间：**  
2025-04-24  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
思迅商旗是深圳市思迅软件股份有限公司的一款零售管理系统。思迅商旗 QueryBackendLog 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="思迅商旗" 对潜在可能目标进行搜索，共得到1988条IP历史记录。主要分布在中国、新加坡等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E6%80%9D%E8%BF%85%E5%95%86%E6%97%97%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONe8u4HibNFrLCicQv6wNWyxVDXLV6GcG4ibvASuLCoIAQmNuBB0Xia4aBEA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONEEwJh9Hh1wdb0PiaDlHHIWkIETUic06qblicflhDEITKbCap7HfgvxIiag/640?wx_fmt=png&from=appmsg "")  
  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**  
，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0y69ibrog5JAntbxrWLWibYONqPFvZRRQibjicdk8ajZo82bV61wN4HTDVcxmVoCVFNghMhFKNwhmqSUg/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
