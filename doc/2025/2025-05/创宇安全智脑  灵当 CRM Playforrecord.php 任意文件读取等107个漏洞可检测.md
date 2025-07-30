#  创宇安全智脑 | 灵当 CRM Playforrecord.php 任意文件读取等107个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2025-05-15 08:57  
  
**创宇安全智脑**  
是基于知道创宇17年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
2025年04月29日至2025年05月14日累计更新漏洞插件107个，其中重点插件10个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmrHCk1TFgMFghdZVRicWXfWJcgK3VFd89R7NFriawNxCxzDxS0CYFHf0g/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞详情  
  
  
**新增插件：**  
  
  
1、灵当 CRM Playforrecord.php 任意文件读取  
  
**发布时间：**  
2025-05-14  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
灵当 CRM 是一款由上海灵当信息科技有限公司开发的客户关系管理软件。灵当 CRM Playforrecord.php 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="灵当 CRM" 对潜在可能目标进行搜索，共得到4955条IP历史记录。主要分布在中国、新加坡等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%81%B5%E5%BD%93%20CRM%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmY1JZFN1oRScBXqzKNUOyaPcHwIXvu6DGfYrVP9mQExP0RYn4kKvwEg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm3D1yiamWTwl4v7el7JHVqhnm4f7qzvgAGh9AE2X2HFlViceqmckOfDQQ/640?wx_fmt=png&from=appmsg "")  
  
  
2、UniBox intraserv.php 远程命令执行  
  
**发布时间：**  
2025-05-14  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
Unibox是一种用于管理任何大小的有线和无线网络的理想设备，它可以部署在咖啡馆/餐馆，酒店/度假村，医院，学校和大学，机场/公交车站，购物中心和私人企业，以管理和控制客人的网络连接。UniBox intraserv.php 接口存在远程命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="UniBox" 对潜在可能目标进行搜索，共得到3026条IP历史记录。主要分布在印度、澳大利亚等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22UniBox%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm4rLwzRgMl67oSaXdoplQUy4WX4WgqNvI2k1DqTmia3sSUULUmTICKzQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibmhmfw5aNDIriaehL8ekpibiaxpjib27ia1QiaTadRPMIafKgw2OPlY8Y90loQ/640?wx_fmt=png&from=appmsg "")  
  
  
3、Wazuh 默认口令  
  
**发布时间：**  
2025-05-13  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
Wazuh 是一个用于威胁预防、检测和响应的免费开源平台。它能够保护本地、虚拟化、容器化和基于云的环境中的工作负载。Wazuh 仪表板存在默认口令。未修改默认密码的情况下，攻击者可以利用默认口令登录系统，获取系统敏感信息。  
  
**漏洞危害：**  
  
未修改默认密码的情况下，攻击者可以利用默认口令登录系统，获取系统敏感信息。  
  
**建议解决方案：**  
  
及时更改默认口令，使用字母大小写、数字、特殊符号的8位以上复杂密码。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Wazuh" 对潜在可能目标进行搜索，共得到12499条IP历史记录。主要分布在美国、德国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Wazuh%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmWOxOqdicpffwQDKVP8baFpVCVvJRiadBMnY7nnLKNIp58ebz9Mic1oCAQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmXjgT0HIYvdyOq2u7hdEM6acvGp6dasKtvCRa3lXTU9NFnFLX1iaOe3Q/640?wx_fmt=png&from=appmsg "")  
  
  
4、SonicWall SMA100 mod_rewrite 任意文件读取  
  
**发布时间：**  
2025-05-12  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38475  
  
**漏洞描述：**  
  
SonicWall SMA100 是一款专为中小企业和分支机构设计的安全远程访问设备。Sonicwall SMA100 10.2.1.13-72sv及之前版本存在 CVE-2024-38475 漏洞。未经授权的远程攻击者可以利用该漏洞，读取系统任意文件。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，读取系统任意文件，造成敏感信息泄露。  
  
**建议解决方案：**  
  
厂商已发布新版本修复该漏洞，请及时升级至10.2.1.14-75sv及以上安全版本。参考链接：  
  
https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0018。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="SonicWall SMA1000" 对潜在可能目标进行搜索，共得到3817条IP历史记录。主要分布在美国、德国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22SonicWall%20SMA1000%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmhCl5BVViaepBNusk3AFpWhKPfJRvXPe2ZI6bj9csbjXHiaMPDiak3X95g/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm4ichLKs9pYGfpqYWmVeSf2atmDnCkuay1ibJnQNbVq7fkY3bsJjJic95Q/640?wx_fmt=png&from=appmsg "")  
  
  
5、  
朗新天霁人力资源管理系统GetBmCodeByTableName SQL注入  
  
**发布时间：**  
2025-05-13  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
朗新天霁人力资源管理系统是一款由北京朗新天霁软件技术有限公司研发的人力资源管理系统。朗新天霁人力资源管理系统 GetBmCodeByTableName 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="朗新天霁人力资源管理系统" 对潜在可能目标进行搜索，共得到617条IP历史记录。主要分布在中国福建、北京等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E6%9C%97%E6%96%B0%E5%A4%A9%E9%9C%81%E4%BA%BA%E5%8A%9B%E8%B5%84%E6%BA%90%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmGoaNh8j2mbmvYfQPDTicrcN1u6zNiaE1pQJvVwicqUjKMOPPRtmiciaMobA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmVCg999WhgmCY3iasdlphHprDgSwia3ayyw4KHEficMhT7CHNkgwIZYxkw/640?wx_fmt=png&from=appmsg "")  
  
  
6、Mage AI 未授权访问  
  
**发布时间：**  
2025-05-13  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
Mage AI 是一个混合数据框架，用于转换和集成数据，支持高效构建、运行和管理数据任务。Mage AI 在未配置访问控制的情况下，允许任意用户访问系统后台并查看配置文件、项目文件、执行终端命令等。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞绕过验证，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时添加访问控制配置，防止出现未授权访问。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Mage AI" 对潜在可能目标进行搜索，共得到568条IP历史记录。主要分布在美国、德国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Mage%20AI%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm4h4bNHD8T5YApLJCiaQKJt8xaorI9lrUakPUKvks85ngRKvAz5ibmVDA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmYBP3dW8o58FzNzgKF0Dible7Wa9nMuYN0cjbrMwnvOOt90zKQVbDffg/640?wx_fmt=png&from=appmsg "")  
  
  
7、润申信息企业标准化管理系统 GetDataBy SQL注入  
  
**发布时间：**  
2025-05-12  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
润申标准化管理系统是润申标准化技术服务（上海）有限公司开发的一个用于企业标准化管理的软件平台。润申信息企业标准化管理系统 GetDataBy 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="润申信息企业标准化管理系统" 对潜在可能目标进行搜索，共得到550条IP历史记录。主要分布在中国北京、上海等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E6%B6%A6%E7%94%B3%E4%BF%A1%E6%81%AF%E4%BC%81%E4%B8%9A%E6%A0%87%E5%87%86%E5%8C%96%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmKiaXL42Ob5AblicAFHPt7COb7wxjl0n8pYtvOYmrsMghmmibZRonhYW6Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibmm3HScM9lOrCTI4A7dReicYlEqVC9y25muZInIKzCdtKU1EQu4TNEU4g/640?wx_fmt=png&from=appmsg "")  
  
  
8、用友U8 Cloud query SQL注入  
  
**发布时间：**  
2025-05-07  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 U8 Cloud 是一款企业级 ERP，用于协助企业实现业务协同和流程管理的高效化和数字化。用友U8 Cloud query 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="用友U8 Cloud" 对潜在可能目标进行搜索，共得到16361条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%94%A8%E5%8F%8BU8%20Cloud%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmKbBhxbL1gO8KhcEkW9szGPUGUZn32g1CYaTMKcpCGWX98ZD9SRic91w/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm3nWBVuouOXFfj8KN4xibNaRJZ519LrlRT0bXrUfGaFmcY3sO907CorQ/640?wx_fmt=png&from=appmsg "")  
  
  
9、用友NC loadDoc.ajax 任意文件读取  
  
**发布时间：**  
2025-05-08  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 NC 是面向集团企业的世界级高端管理软件。用友NC loadDoc.ajax 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Yonyou NC httpd" 对潜在可能目标进行搜索，共得到15356条IP历史记录。主要分布在中国、马来西亚等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Yonyou%20NC%20httpd%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmNjsdeib0YcsgfvRAA1ux0dgVQaJT6CFiazSImQRqMR7LVlAb6eOJTS3g/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm5Lxqw5oJIwwHvynZxDYdqeSMVn7b4tQZRTrbJEWIBo5JOA5na4tvug/640?wx_fmt=png&from=appmsg "")  
  
  
10、大唐电信AC集中管理平台 ac_upgrade 任意文件读取  
  
**发布时间：**  
2025-05-06  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
大唐电信 AC 集中管理平台是大唐电信科技股份有限公司研发用于集中管理和监控网络设备、服务或资源包括网络设备配置、性能监控、安全管理等功能的一体化产品。大唐电信AC集中管理平台 ac_upgrade 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="大唐电信AC集中管理平台" 对潜在可能目标进行搜索，共得到555条IP历史记录。主要分布在中国四川、重庆等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E5%A4%A7%E5%94%90%E7%94%B5%E4%BF%A1AC%E9%9B%86%E4%B8%AD%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibm9Qq2VPj60fKp9ibU8ugBFiaboK0UtWyxUc6Oib0tgwdLicoIoZtt9D5W2A/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9Kibmm5vibx3mxUqXAXoSbC5L0BJXnOPAmPibGzEnicIZvQeGz6ibIWBAkuVTYQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**  
，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0yFbOghrMaP394DSibbg9KibmR9UbrFqZYMssIjmQB3r4T78rzyVkicNn9QTO2iadxMzQvZCukXwDqC8w/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
