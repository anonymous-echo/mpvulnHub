#  创宇安全智脑 | 时空智友企业流程化管控系统 indexService.notice SQL注入等88个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2025-04-24 09:22  
  
**创宇安全智脑**  
是基于知道创宇17年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件88个，其中重点插件10个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HTqqPVWhnTkRic41ZjeSLjBvSwSmAUNuutI9CDIQjdYE8O0bmj0YnkSg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞详情  
  
  
**新增插件：**  
  
  
1、用友U8 Cloud rewrite SQL注入  
  
**发布时间：**  
2025-04-23  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 U8 Cloud 是一款企业级 ERP，用于协助企业实现业务协同和流程管理的高效化和数字化。用友U8 Cloud rewrite 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="用友U8 Cloud" 对潜在可能目标进行搜索，共得到16144条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%94%A8%E5%8F%8BU8%20Cloud%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HYDhh9C8s1xmuc3KU7CT6FOg0GUIjrg1SWJUA58eBUMkZCPQNJ0d6ag/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HfzBeJYZzpwO3Brym7I1hggbw9fgxKWsEhxzcZ1ibXttASE2qRrjnJ3g/640?wx_fmt=png&from=appmsg "")  
  
  
2、NetMizer 日志管理系统 troubleip.php 远程命令执行  
  
**发布时间：**  
2025-04-22  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
NetMizer 日志管理系统是一种用于管理和监控计算机网络活动和日志的软件系统。NetMizer 日志管理系统 troubleip.php 接口存在系统命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="NetMizer 日志管理系统" 对潜在可能目标进行搜索，共得到473条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22NetMizer%20%E6%97%A5%E5%BF%97%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2H2pib0tlL5ySfZg2XAReZxyAN3HyffNv6o5xMoMrCDmB5QTTJUQicLuSw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2H2AChboJhKMf4N5jj2HaqRhaOibguVvHUT6Qlo7109Bb1vt2xwvTby2A/640?wx_fmt=png&from=appmsg "")  
  
  
3、广州图创图书馆集群管理系统 getCommendBook SQL注入  
  
**发布时间：**  
2025-04-23  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
广州图创图书馆集群管理系统是一款为图书馆设计的综合性管理软件。广州图创图书馆集群管理系统 getCommendBook 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="广州图创图书馆集群管理系统" 对潜在可能目标进行搜索，共得到844条IP历史记录。主要分布在中国山东、上海等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E5%B9%BF%E5%B7%9E%E5%9B%BE%E5%88%9B%E5%9B%BE%E4%B9%A6%E9%A6%86%E9%9B%86%E7%BE%A4%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HVNrHViamj4PGV4435D5Om8PN6uyTWricYe1hb1HlB8rC0tX6AsTOaic3Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HVHjAL4kDu8wObHO7krqUsLF0oGlIqvgrWlhe7fuOnCnAfa4D9cicygQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、时空智友企业流程化管控系统 indexService.notice SQL注入  
  
**发布时间：**  
2025-04-22  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
时空智友企业流程化管控系统是一个功能丰富、灵活可定制的企业管理工具。时空智友企业流程化管控系统 indexService.notice 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="时空智友企业流程化管控系统" 对潜在可能目标进行搜索，共得到4053条IP历史记录。主要分布在中国山西、湖北等地。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E6%97%B6%E7%A9%BA%E6%99%BA%E5%8F%8B%E4%BC%81%E4%B8%9A%E6%B5%81%E7%A8%8B%E5%8C%96%E7%AE%A1%E6%8E%A7%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HXQicaDCHkthE9L2nldvsicxtFAanib0pb5iaiaUnlFovP8FZJdyp7ZOkYrw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HkibgXLkoT1XsMcTGteZ20WByttibJ9LxOJnRjVyz4JjndeXicnC4IVWyQ/640?wx_fmt=png&from=appmsg "")  
  
  
5、  
用友U8 Cloud callback SQL注入  
  
**发布时间：**  
2025-04-18  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 U8 Cloud 是一款企业级 ERP，用于协助企业实现业务协同和流程管理的高效化和数字化。用友U8 Cloud callback 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="用友U8 Cloud" 对潜在可能目标进行搜索，共得到16144条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%94%A8%E5%8F%8BU8%20Cloud%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HYDhh9C8s1xmuc3KU7CT6FOg0GUIjrg1SWJUA58eBUMkZCPQNJ0d6ag/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HCWyMakzKaBTrMQz71dZMkxYicRpiajHiaibYsDa8f9DHCS2JuicGrf52toA/640?wx_fmt=png&from=appmsg "")  
  
  
6、Whoogle 搜索引擎 < v0.9.1 pickle 反序列化远程代码执行（CVE-2024-53305）  
  
**发布时间：**  
2025-04-18  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-53305  
  
**漏洞描述：**  
  
Whoogle 搜索是一款自托管、无广告且尊重隐私的元搜索引擎。Whoogle 搜索引擎在 v0.9.1版本以前存在 pickle 反序列化代码执行漏洞。恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
厂商已发布更新修复该漏洞，请及时更新到最新安全版本。参考链接：https://github.com/benbusby/whoogle-search。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="Whoogle 搜索引擎" 对潜在可能目标进行搜索，共得到1215条IP历史记录。主要分布在美国、德国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22Whoogle%20%E6%90%9C%E7%B4%A2%E5%BC%95%E6%93%8E%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HFC0CSZE4hvTWS6CwzMI0xw0vHEwHUOAtv0wXmnS3dGQibHdY5fsoRxA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HibgxXrf9Znyc6ATyXgsrMNXgCViaNeNeVMnOKBencGeB0aocRb2dDsGw/640?wx_fmt=png&from=appmsg "")  
  
  
7、用友U8 Cloud er.ydbx.writeoff.query SQL注入  
  
**发布时间：**  
2025-04-21  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
用友 U8 Cloud 是一款企业级 ERP，用于协助企业实现业务协同和流程管理的高效化和数字化。用友U8 Cloud er.ydbx.writeoff.query 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="用友U8 Cloud" 对潜在可能目标进行搜索，共得到16144条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%94%A8%E5%8F%8BU8%20Cloud%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HYDhh9C8s1xmuc3KU7CT6FOg0GUIjrg1SWJUA58eBUMkZCPQNJ0d6ag/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HjB2iaK46OMgTPuH9PSA2AfBnWEZqzahIeJrKqybz6Bp2r2an1pROCNg/640?wx_fmt=png&from=appmsg "")  
  
  
8、NetMizer 日志管理系统 mail.php 远程命令执行  
  
**发布时间：**  
2025-04-17  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
NetMizer 日志管理系统是一种用于管理和监控计算机网络活动和日志的软件系统。NetMizer 日志管理系统 mail.php 接口存在系统命令执行漏洞。恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，确保使用时进行输入验证，以防止参数中存在恶意的命令执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="NetMizer 日志管理系统" 对潜在可能目标进行搜索，共得到473条IP历史记录。主要分布在中国、美国等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22NetMizer%20%E6%97%A5%E5%BF%97%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HickyVcgBfuicsOX5VFCuFic0J6uXPHc0DOFf70roLc5dAgpQibhdcHkUIg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HQhcfzRKVFmicskzAsQFrB2AksbqjNUO5B3ShXzSRJyjj0pBFpFJ1u2w/640?wx_fmt=png&from=appmsg "")  
  
  
9、科拓全智能停车视频收费系统 GetAdSubByID SQL注入  
  
**发布时间：**  
2025-04-17  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
科拓全智能停车视频收费系统是一款由厦门科拓通讯技术股份有限公司开发的一体化智能停车收费系统。科拓全智能停车视频收费系统 GetAdSubByID 接口存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="科拓全智能停车视频收费系统" 对潜在可能目标进行搜索，共得到559条IP历史记录。主要分布在中国、俄罗斯。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%A7%91%E6%8B%93%E5%85%A8%E6%99%BA%E8%83%BD%E5%81%9C%E8%BD%A6%E8%A7%86%E9%A2%91%E6%94%B6%E8%B4%B9%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HWhHiccNqmpVvyBfLR4uzI4IC6gbgMbFzibgIblw87ibDibal3V4C98EeKg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HxcrbDaZmbZ1aEnvGlpbzF7Vw2dI7nsemMTWWKfhYUx9Mhhr3Bqma3Q/640?wx_fmt=png&from=appmsg "")  
  
  
10、科立讯指挥调度管理平台 download.php 任意文件读取  
  
**发布时间：**  
2025-04-17  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
科立讯指挥调度管理平台是一个针对通信行业的指挥调度管理平台。科立讯指挥调度管理平台 download.php 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，严格过滤用户输入字符的合法性，比如文件类型、文件地址、文件内容等，并确保使用时进行输入验证和过滤，以防止参数中包含非法字符。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app="科立讯指挥调度管理平台" 对潜在可能目标进行搜索，共得到708条IP历史记录。主要分布在中国、菲律宾等国家。  
  
（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3D%22%E7%A7%91%E7%AB%8B%E8%AE%AF%E6%8C%87%E6%8C%A5%E8%B0%83%E5%BA%A6%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HX0cI7acnVez9X2kzlGKvaROmOVJdscg5ORjGk6HTvx5o5BUBkjAiaeQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HpO6iaR5WvTjfYkdoNrLUnJR3kyYUfFhvP49nxqs6ianFYboHzxMDibzFQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**  
，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wPFnD74uEgLeJbmf0plm2HoeN3wr0EsoHp2D7IOI35bdnn3swY17vfbqibXw5aibv2HymwuyOlbnRA/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
  
