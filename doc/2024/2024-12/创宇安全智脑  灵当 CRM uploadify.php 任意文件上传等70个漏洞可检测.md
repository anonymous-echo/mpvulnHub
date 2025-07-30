#  创宇安全智脑 | 灵当 CRM uploadify.php 任意文件上传等70个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2024-12-19 09:50  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件70个，其中重点插件4个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHOnaEAuDLIhicVFU8oZhIwc3qvg6WzvhYWoc5Po8n6LXY4fWEJdGm81A/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、灵当 CRM uploadify.php 任意文件上传  
  
**发布时间：**2024-12-18  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
灵当 CRM 是一款由上海灵当信息科技有限公司开发的客户关系管理软件。灵当 CRM uploadify.php 接口存在任意文件上传漏洞。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="灵当 CRM" 对潜在可能目标进行搜索，共得到4768条IP历史记录。主要分布在中国、新加坡等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLngbXlvZMgQ1JNIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHVibKHkXPdYuzViaGfRVpQW4eysst8QmSL88ib80OsoV8UXd4U502N4D0A/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHtrQDN2M1vJiapVkPtI36aJ9PDwEnxMa1yIYezuYiaKfrSGpFylhkLr0A/640?wx_fmt=png&from=appmsg "")  
  
  
2、圣乔ERP系统 queryForString.dwr SQL注入  
  
**发布时间：**2024-12-16  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
圣乔ERP系统是杭州圣乔科技有限公司开发的一款企业级管理软件。圣乔ERP系统 queryForString.dwr 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="圣乔ERP系统" 对潜在可能目标进行搜索，共得到353条IP历史记录。主要分布在中国浙江、江苏。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLlnKPkuZRFUlDns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHzeVdr1CRkxzgSDoeLia4sUHQannAML3M55YKBBfBPiaB6f6jL6Fv5icow/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHScm5icia6fZFMkWh0u0s7nuP0dV24uWGQxt7ajtosqWYVYQnzDfzNnGQ/640?wx_fmt=png&from=appmsg "")  
  
  
3、圣乔ERP系统 uploadFile.action 任意文件上传  
  
**发布时间：**  
2024-12-16  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
圣乔ERP系统是杭州圣乔科技有限公司开发的一款企业级管理软件。圣乔ERP系统 uploadFile.action 接口存在任意文件上传漏洞。结合系统权限绕过漏洞，远程攻击者可绕过认证授权上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="圣乔ERP系统" 对潜在可能目标进行搜索，共得到353条IP历史记录。主要分布  
在中国浙江、江苏。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLlnKPkuZRFUlDns7vnu58i）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHzeVdr1CRkxzgSDoeLia4sUHQannAML3M55YKBBfBPiaB6f6jL6Fv5icow/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHScm5icia6fZFMkWh0u0s7nuP0dV24uWGQxt7ajtosqWYVYQnzDfzNnGQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、中科商软-云连ERP file!download.action 任意文件读取  
  
**发布时间：**2024-12-17  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
云连ERP是北京中科商软软件有限公司开放的一款企业资源计划管理系统。中科商软-云连ERP file!download.action 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="中科商软-云连ERP" 对潜在可能目标进行搜索，共得到164条IP历史记录。主要分布在中国、印度等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/v2/searchResult?q=YXBwPSLkuK3np5HllYbova8t5LqR6L%2BeRVJQIg%3D%3D）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHWwTXI6HACvc5Kawl2TOGZ1Q5OOyUsS3LgViaWwPqgibRKicFxUibZylmqA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHQX7PU8ZxiblFvoZIL4VFUjo1ajeFtPf4hnB2vwibiaJIqtY9AvDicQY8iag/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wuDLDjLYEa7BOz8iaBHWCoHOcax2MzHCyuzmL22GTYwXXCb75IW6lAwcJ4MuCQ5bX0LyzxlvPerSg/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
