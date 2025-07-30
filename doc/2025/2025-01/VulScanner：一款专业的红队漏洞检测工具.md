#  VulScanner：一款专业的红队漏洞检测工具   
 泷羽Sec-醉陌离   2025-01-14 10:00  
  
# VulScanner  
>   
> 一款适合在渗透测试中随时记录和保存的漏洞检测工具  
  
>   
> 项目地址：https://github.com/cn-xwhat/VulScanner  
  
>   
> 文末有详细配置教程  
  
#### 一、 主要模块  
## 主要功能模块  
1. **任务管理**  
：  
  
1. 支持扫描任务、FOFA 采集、IP 段采集。  
  
1. 任务进度实时可视化，便于跟踪。  
  
1. **POC 管理**  
：  
  
1. 内置多种常见漏洞的 POC（Proof of Concept）。  
  
1. 支持自定义 POC 并进行模块化管理。  
  
1. **服务扫描**  
：  
  
1. 支持对目标进行服务的快速识别和扫描。  
  
1. **漏洞扫描**  
：  
  
1. 集成多种漏洞检测功能，包括弱密码检测、命令执行、未授权访问等。  
  
1. **FOFA 采集和 IP 段采集**  
：  
  
1. 融合 FOFA 数据，支持目标资产的快速采集。  
  
#### 01 任务列表  
>   
> 示例  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTM2fticAiatU7HM2k9aJ07FQCicjJUjRlG3ueE7mgP0ylOYibzGJeJSbicNg/640?wx_fmt=png&from=appmsg "")  
  
**实现功能：**  
1. 可视化服务扫描结果，对于扫描进度实时显示，点击“服务扫描”或“漏洞扫描”进度标签可查看扫描结果  
  
**使用说明**  
1. 可点击“笔”图标对任务描述进行即时修改，方便任务管理  
  
1. 可根据ip范围和扫描进度对结果进行过滤：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTy1qtticFhwPhAPkoYicyQbYVUlibKhTs9mIpfHuGLbHzJyZX4G2uzg8gw/640?wx_fmt=png&from=appmsg "")  
1. 点击“新建任务”，可创建服务扫描或漏洞扫描任务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTW90RLz7ovLpxLFiatFicS78ibicfoUkTicbAAJa72hqqiasprTVOl2RDkztQ/640?wx_fmt=png&from=appmsg "")  
1. 对于FOFA采集与IP段采集等结果也采取可视化列表形式查看：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBT5QtXI0HR12NlU46Ctmib5YrZvU6ic4y5Km7ZNvznVJp3lovvOaNxA0Og/640?wx_fmt=png&from=appmsg "")  
#### 02 POC列表  
>   
> 示例  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTTsicppLELVE3uNFrXT1gqG4pIE6ZDwoxTsWfR3l8mydL818veswtfQQ/640?wx_fmt=png&from=appmsg "")  
  
**实现功能：**  
1. 工具内置34种常见且危害性较高的漏洞检测模块，可点击启用图标设置该模块是否启用，并可一键启/禁用，方便调试  
  
1. 可根据类型查看相应POC，方便信息整理  
  
**使用说明：**  
1. 添加POC时根据漏洞相应信息填写各栏：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTwzCzTrI3QR2ZKmtvsVMQpAFA6tfUAul0SPBAVtllD2gJbxCUgGvcTg/640?wx_fmt=png&from=appmsg "")  
  
如该漏洞可实现方便的exp攻击，可同时选择exp类型：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTTWpzklUeGfiaKibiaibqAZCj8olxMc1HRJjFKtX29Tn4S6mxs4Fx6iaqTUQ/640?wx_fmt=png&from=appmsg "")  
  
并可在后续的漏洞扫描中根据不同类型的exp进行调用  
  
2.提交poc名称后，module目录下会自动生成 ‘poc名称_poc.py’，如具有exp，将同时生成‘poc名称_exp.py’，漏洞检测时会根据poc名称进行反射调用，故请勿修改文件名：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTSq4wlQH0R7MH7uYAJargEJTUYkKItbHNqUFH9bexyUTFibsSv03DUaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTecXJ6JYxRQcic6YQvR2gM45icoX8IsSQBXOq8RlibRUj6iaNVsJxvKE1Cg/640?wx_fmt=png&from=appmsg "")  
  
poc和exp脚本初始化为模板文件，并对requests和文件操作函数进行封装，可根据具体验证方法修改文件，大致逻辑如下：  
```

poc.py:

    def fingerprint(service):   #进行漏洞检测前首先进行指纹识别，如满足指纹则继续验证

        if (指纹识别):

            return True #如指纹识别结果需保存，可返回Str并保存至service.speciality

        else:

            return False



    def poc(service):   进行漏洞检测

        if (存在漏洞):

            return ['漏洞名（自动生成）',  '具体情况', ('漏洞等级（可选）')] #如漏洞检测需返回特殊结果，可用元组形式返回：（[与前一致], '特殊结果'），其中特殊结果保存至vuln.specify





exp.py:

    def exp(vuln):

        return "命令执行结果"




```  
  
**具体模块：**  
- **弱密码类型：**  
  
1. 数据库弱密码：  
  
1. 包含mysql、mssql、redis、postgresql数据库弱密码检测功能  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTibEibWzgSib1ZephyycjsjpiaibpB9Na1ZVfHK1WHOQXjFrQDVT7vIbZLCg/640?wx_fmt=png&from=appmsg "")  
1. tomcat弱密码：  
  
1. 采用metasploit内置tomcat弱密码字典，注意tomcat自带密码保护机制，大量爆破可能导致manager用户被禁用  
  
1. 爆破成功后可执行exp，自动部署webshell目录下zs.war包并可执行命令  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTWp4z1kzU0yyTvrkIvkUkRDnwj5yaYIaUctSVy1nDPju8WO1gqbibV2A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBT3VXXeJibPtnDkYXuOvZ9AqoVgCSLfOzeGX4jOibcm2pX50PibgjB21eeQ/640?wx_fmt=png&from=appmsg "")  
1. axis2弱密码：  
  
1. 自动探测axis2目录，如存在axis2-admin目录则尝试以admin/axis2登录  
  
1. 登陆成功后可执行exp，自动部署webshell下aar包并可执行命令  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTQiaB5oMMvSUGJOStdZVGPv5tyicPPRRiahLSGicA0lvS0iakvLkaHXgpt6A/640?wx_fmt=png&from=appmsg "")  
1. weblogic控制台弱密码：  
  
1. 自动探测是否开放console路径，并尝试爆破，爆破成功则返回用户名/密码  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTbUrcy7wXp9M3vpF5T02gH9Lt8D31FkbFQrWkXiciasyKbaHkBaksVoaA/640?wx_fmt=png&from=appmsg "")  
1. Zyxel 硬编码后门账户：  
  
1. 尝试以zyfwp/PrOw!aN_fXp登录ftp端口，如登陆成功则返回漏洞结果  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTU2uRKutzXKX1eicFS2tiakSTFswVsmW32ic3lP5Au29PfAeXv2WnHFY4g/640?wx_fmt=png&from=appmsg "")  
1. daloradius弱密码（0day）  
：  
  
- 尝试以默认密码登录  
  
- 登陆成功可执行exp，可上传文件至网站根目录  
  
- 示例：  
  
1. 部分安全设备密码泄露：  
  
1. 对中科网威等安全设备前端泄露密码进行探测并返回结果  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTnVYRLKstvgFGbhNHR7yTzVZOwgoJZFicewnEptCZ7gqSEbeM2XF3RRQ/640?wx_fmt=png&from=appmsg "")  
1. ssh弱密码：  
  
1. 对22端口进行爆破登录  
  
1. 如爆破成功则可使用命令执行exp：  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTkjxtcD7RCdL0QKoSeFjL6b2PBCoBxyXJBcUdO7Nniaiauv37ZSLgDA4A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTQ7G6pHoT99nu8mX9Hc5OfXde96HSiaLctCMHXfPiciaFWicZLZKsiaTaBEA/640?wx_fmt=png&from=appmsg "")  
- **命令执行类型**  
  
1. shiro反序列化：  
  
1. 对常见key进行探测，支持cbc/gcm加密方式，采用SimplePrincipalCollection的payload，可不出网测试  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTqPwecaZRicXf38J1LDMSdqJYIy36cPb7Giatia9kJOjoow6LGbcQAeB8w/640?wx_fmt=png&from=appmsg "")  
1. 浪潮管理系统V4.0 RCE：  
  
1. 支持未授权登录/登录接口RCE/SysShel接口RC!  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTQSABTUD8YEPCRoMFRsgrgmxbdDiagKU6C8qm5qjFic8Q48DXlA17nRNg/640?wx_fmt=png&from=appmsg "")  
```
*  如存在SysShell接口RCE漏洞，可使用命令执行exp：

*  示例：

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTzzEhdUDzYWVh4wDdw7ELLbI9yvOUXiaLsHrx0aZ1kMYpyOrI1Srj8EQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTQSABTUD8YEPCRoMFRsgrgmxbdDiagKU6C8qm5qjFic8Q48DXlA17nRNg/640?wx_fmt=png&from=appmsg "")  
1. 用友OA BshServlet接口泄露：  
  
1. 探测是否开放BshServlet接口  
  
1. 如存在漏洞，则可使用命令执行exp  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTF7Pc3zYBUmiaYGiaCsC1KzA6ibaz1ZPKjvzNo5NflQn2F8TWtsQOgpbNg/640?wx_fmt=png&from=appmsg "")  
1. docker未授权漏洞：  
  
1. 探测是否可访问info路径  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTBb5nc7sYyaUpWRDbrX88TxN6Mrq6LQJc7fkUuEVfAOFGcVXNibh5Wicg/640?wx_fmt=png&from=appmsg "")  
1. Thinkphp debug命令执行：  
  
1. 测试是否可调用debug模块执行代码  
  
1. 如存在漏洞，则可使用命令执行exp  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTB0iaNbGtkaoI4tcTnZ2Uvmt3tDR8oSRa0HVicTzPRCdIU84yDyZzDeuA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTTehqV3lF4ztpeFcI644HORmsXZTKxfafq7rSC4qAnffq3B90ftEd6Q/640?wx_fmt=png&from=appmsg "")  
1. Thinkphp5命令执行：  
  
1. 测试是否可调用index/think/app/invokefunction模块执行代码  
  
1. 如存在漏洞，则可使用命令执行exp  
  
1. 示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBT3ChtRo93lNvHqkEuYq88owDKJIhgDJGVBMibj7FhPQWPJyN6MRByv3A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTeYacWAcJl9VCr9K582CHHHfYp4ibiac0iadFCYVpoeYHncd6OCy5hVDmg/640?wx_fmt=png&from=appmsg "")  
1. weblogic_XML反序列化：  
  
1. 上传文件测试是否存在XML反序列化漏洞  
  
1. 如存在漏洞，则可使用文件上传exp  
  
1. weblogic_wls9-async反序列化：  
  
1. 利用@lufei大佬的poc测试，如有命令回显则存在漏洞  
  
1. 如存在漏洞，则可使用命令执行exp  
  
1. MS17_010：  
  
1. 不多说了  
  
1. Apache Solr Velocity模板远程执行：  
  
1. 首先未授权获取目标全部core，再以此测试是否可修改params.resource.loader.enabled值，如可修改，则返回并保存，以供exp使用  
  
1. 如存在漏洞，可使用命令执行exp  
  
1. 泛微OA_XML反序列化：  
  
1. 采用URLDNS模块测试  
  
1. 目前大部分系统均已修复，且进一步利用条件较为困难，故不提供exp  
  
1. 奇安信 网康下一代防火墙RCE：  
  
1. 通过写入命令至文件方式利用，如写入成功，则存在漏洞  
  
1. 如存在漏洞，可使用命令执行exp  
  
1. H3C SecParh堡垒机远程命令执行：  
  
1. 首先通过未授权获取管理员权限，再代码注入执行命令  
  
1. 如存在漏洞，则可使用命令执行exp  
  
###**篇幅有限需要看完整版可以访问原项目查看**  
#### 0x07 配置与使用  
1. 下载后请修改config.ini文件的数据库配置，仅支持mysql数据库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTRLHT6Rwew3LTzrFy7dcJhkoHhFicbmQXTMr7jwXBfAZGhkYMO70Uy6Q/640?wx_fmt=png&from=appmsg "")  
1. 登录mysql数据库创建名为scan的数据库  
  
1. 命令行安装所需第三方库：pip install -r requirements.txt  
  
1. django初始化配置：  
  
python manage.py makemigrations  
  
python manage.py migrate  
  
1. 配置初始poc：  
  
python install.py  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBT4ajbuiajH3m9l8am6AEmrHJZzwVa5SRsE7evjMkdiby6ewAvMuwOYO9w/640?wx_fmt=png&from=appmsg "")  
1. 启动django服务器:  
  
python manage.py runserver  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBT8gyLiabhD0OUJLP1UaaOAHC5talRUy99ickU60Mm5nH74icL62ibhjPWQQ/640?wx_fmt=png&from=appmsg "")  
1. 访问  
http://127.0.0.1:8000/  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GOiczibvxk0XStxJewIaYwNtfOKEcb4JBTBFFtgboKiaPI4giakZpgM1IADY5Vs4vYxtbWzbIibsvAXZlicn5ibfadY3A/640?wx_fmt=png&from=appmsg "")  
  
  
>   
> 免责声明：  
> 该文章所涉及到的安全工具和技术仅做分享和技术交流学习使用，使用时应当遵守国家法律，做一位合格的白帽专家。  
> 使用本工具的用户需要自行承担任何风险和不确定因素，如有人利用工具做任何后果均由使用者承担，本人及文章作者还有泷羽sec团队不承担任何责任。  
> 如果侵权请联系作者删除文章！  
  
  
  
****  
> ****  
> **本文中所涉及到的资料已经全部给各位看官老爷准备并且打包好了，后台回复“8366”即可获取**  
>   
  
  
  
