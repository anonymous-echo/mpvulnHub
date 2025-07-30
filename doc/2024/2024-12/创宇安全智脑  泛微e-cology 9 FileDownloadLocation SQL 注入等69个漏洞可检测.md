#  创宇安全智脑 | 泛微e-cology 9 FileDownloadLocation SQL 注入等69个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2024-12-26 09:56  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件69个，其中重点插件8个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3Y0GLuFlrBWyy7cQR8tktokdYVoFIlQaicYQc6UOt5WrItr4Ipz9CSnQ/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、方正畅享全媒体新闻采编系统 reportCenter.do SQL注入  
  
**发布时间：**2024-12-20  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
方正畅享全媒体新闻生产系统是以内容资产为核心的智能化融合媒体业务平台，融合了报、网、端、微、自媒体分发平台等全渠道内容。方正全媒体采编系统 reportCenter.do 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="方正全媒体采编系统" 对潜在可能目标进行搜索，共得到934条IP历史记录。主要分布在中国、马来西亚。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLmlrnmraPlhajlqpLkvZPph4fnvJbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3eibBOTu2wShLTKxhIOJDiaGice4k1nZrFNHByXhEFicsApRYVXAxmiauB1w/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3rAeRh3Rd5VTRA7W6sZJ4GXic6zjaAFO7mOAzunjWBCnfibvEXnyvUoyA/640?wx_fmt=png&from=appmsg "")  
  
  
2、方正畅享全媒体新闻采编系统 screen.do SQL注入  
  
**发布时间：**2024-12-20  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
方正畅享全媒体新闻生产系统是以内容资产为核心的智能化融合媒体业务平台，融合了报、网、端、微、自媒体分发平台等全渠道内容。方正全媒体采编系统 screen.do 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="方正全媒体采编系统" 对潜在可能目标进行搜索，共得到934条IP历史记录。主要分布在中国、马来西亚。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult/report?q=YXBwPSLmlrnmraPlhajlqpLkvZPph4fnvJbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3eibBOTu2wShLTKxhIOJDiaGice4k1nZrFNHByXhEFicsApRYVXAxmiauB1w/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3rAeRh3Rd5VTRA7W6sZJ4GXic6zjaAFO7mOAzunjWBCnfibvEXnyvUoyA/640?wx_fmt=png&from=appmsg "")  
  
  
3、Cloudlog request_form SQL注入  
  
**发布时间：**  
2024-12-19  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
Cloudlog 是一个自托管的 PHP 应用程序，可让您在任何地方记录您的业余无线电联系人，您只需要一个网络浏览器和有效的互联网连接。Cloudlog request_form 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Cloudlog" 对潜在可能目标进行搜索，共得到298条IP历史记录。主要分布在德国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJDbG91ZGxvZyI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3Jdv17r4WMOLZjAnfwYIIaOyq6cWKPa69h3lRpuxKsQgMtHUCu7NeIQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3ia2nEXHFhBPcMiaGrNZa89icS4JFkGymQeTvvcrhCxz9Wbzhn0P5boNwA/640?wx_fmt=png&from=appmsg "")  
  
  
4、汉明无线管理控制系统 exportConfigByHttp 信息泄露  
  
**发布时间：**2024-12-25  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
汉明无线管理控制系统是一款由苏州汉明科技有限公司开发的无线通信管理软件。汉明无线管理控制系统 exportConfigByHttp 接口存在信息泄露漏洞。未经授权的远程攻击者可以利用该漏洞，获取用户名、密码、IP地址等敏感信息。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，获取用户名、密码、IP地址等敏感信息。  
  
**建议解决方案：**  
  
及时更新至最新版本，实施严格的访问控制机制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="汉明无线管理控制系统" 对潜在可能目标进行搜索，共得到374条IP历史记录。主要分布在中国广东、湖南等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLmsYnmmI7ml6Dnur%2FnrqHnkIbmjqfliLbns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3Pvf5UGrctnlzbgMYzD3qDheKZHLh4R07R5bzSibo58TEuexQpmdjyXw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3DDZVZPP7dUVWVu7Kg9MnuUGq7T9VzQGC5QUuYSQWwkUPjSialxvTg0Q/640?wx_fmt=png&from=appmsg "")  
  
  
5、Craft CMS register_argc_argv 远程代码执行（CVE-2024-56145）  
  
**发布时间：**2024-12-25  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-56145  
  
**漏洞描述：**  
  
Craft CMS 是一款灵活、用户友好的 CMS，用于在网络及其他领域创建自定义数字体验。当 php.ini 配置开启 register_argc_argv 时，Craft CMS 存在远程代码执行漏洞。恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
1、在 php.ini 配置中关闭 register_argc_argv；2、更新Craft CMS至3.9.14、4.13.2 或 5.5.2及以上安全版本。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Craft CMS" 对潜在可能目标进行搜索，共得到173687条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSJDcmFmdCBDTVMi）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3wfNIficU9gSZ1xQQ2NvHKIgicrZYmteduRUqjuyJiakFERQfRM0D00QoQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3PBM35KdpJnI1a9xLf1PfmjPibfXPfOKFd40uOtN9CYQIUsvm8ua6icTw/640?wx_fmt=png&from=appmsg "")  
  
  
6、泛微e-cology 9 FileDownloadLocation SQL 注入  
  
**发布时间：**2024-12-24  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
泛微协同管理应用平台（e-cology）是一款全面的企业管理平台。泛微 e-cology 9 FileDownloadLocation 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="泛微协同管理应用平台e-cology" 对潜在可能目标进行搜索，共得到87036条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLms5vlvq7ljY%2FlkIznrqHnkIblupTnlKjlubPlj7BlLWNvbG9neSI%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3jK4iaibmbo8PSrDvq2JstZJM5uv1OYUr05RmZkHdh4NibgPHIooYXsISg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3ZvayY2daIxk6pRnyH96ZbZRqXgJiaYRCsoJO0WaTpR6b0f5Hk6O2ficw/640?wx_fmt=png&from=appmsg "")  
  
  
7、网动统一通信平台 iactiveEnterMeeting.action 敏感信息泄露  
  
**发布时间：**2024-12-24  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
网动统一通信平台是一款即时通信客户端。网动统一通信平台 iactiveEnterMeeting.action 接口存在敏感信息泄露漏洞。未经授权的远程攻击者可以利用该漏洞，获取password、username、roompwd等敏感信息。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，获取password、username、roompwd等敏感信息。  
  
**建议解决方案：**  
  
及时更新至最新版本，实施严格的访问控制机制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="网动统一通信平台" 对潜在可能目标进行搜索，共得到366条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLnvZHliqjnu5%2FkuIDpgJrkv6HlubPlj7Ai）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3bYTBwWSHibANNEcWicUgkoUjoq38EtNSNgrsOOYFqo5MroylP12awrqA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3WBs7shibUkdeenJ64luqzWKZJgz5aoRrsMknS96gK3uzWvFzITCzCVA/640?wx_fmt=png&from=appmsg "")  
  
****  
8、蓝凌 EKP webservice 任意文件读取  
  
**发布时间：**2024-12-23  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
蓝凌 EKP（Enterprise Knowledge Portal，企业知识门户）是由深圳市蓝凌软件股份有限公司开发的一款面向大中型企业的数字化办公平台。该系统结合了传统OA 的办公特点和企业管理信息化的趋势，旨在提升企业的协同能力和工作效率。蓝凌 EKP webservice 多接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="蓝凌 EKP" 对潜在可能目标进行搜索，共得到2648条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=YXBwPSLok53lh4wgRUtQIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3XoIiaLPS8THYSNMycOwIWZTGkvlZoamrv9cIzU2TrZQHJ6x7bl3jJSw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3oMxkIdquBaSaVIaOHiaz8In9vRzcldLKoWickXr4hSOfkAB12h0pibDkg/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yqBfSkIZWY5BzBoXjclEX3uq4TJnELBvt8iaZicbx86CPewOpDPY2dbIwcII2biaatH1CSBicOvAkJUw/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
