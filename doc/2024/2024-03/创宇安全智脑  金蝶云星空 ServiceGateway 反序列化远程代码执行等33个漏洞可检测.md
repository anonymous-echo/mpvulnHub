#  创宇安全智脑 | 金蝶云星空 ServiceGateway 反序列化远程代码执行等33个漏洞可检测   
原创 创宇安全智脑  创宇安全智脑   2024-02-29 17:21  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
本周累计更新漏洞插件33个，其中重点插件11个  
  
**详情如下：**  
  
  
**更新列表**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7dV44C5lgq3GuIuVMYPiclEVOoVCIEmibOdqSlP3Ud0qXrERmKZR2oSLA/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞详情**  
  
  
**新增插件：**  
  
  
1、网神 SecGate 3600 防火墙sys_export_conf_local_save 任意文件读取  
  
**发布时间：**2024-02-28  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
奇安信网神SecGate3600防火墙是一款能够全面应对传统网络攻击和高级威胁的创新型防火墙产品，可广泛运用于政府机构、各类企业和组织的业务网络边界，实现网络安全域隔离、精细化访问控制、高效的威胁防护和高级威胁检测等功能。网神 SecGate 3600 防火墙存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，并严格限制文件读取权限。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"网神SecGate 3600防火墙" 对潜在可能目标进行搜索，共得到2965条IP历史记录。主要分布在中国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22%E7%BD%91%E7%A5%9ESecGate%203600%E9%98%B2%E7%81%AB%E5%A2%99%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I779rKrN0tS5ERvX405aaDlPcksesziciaHSg6ZBwHtticd0dZEEzQBLSiaw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7ccz1NtlF8hqlNsfWvrCTrgUriaKDKc1ggnfviczQrluBib8d3oYTwHXLA/640?wx_fmt=png&from=appmsg "")  
  
  
2、H3C 校园网自助服务系统 flexfileupload 任意文件上传  
  
**发布时间：**2024-02-27  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
H3C 校园网自助服务系统是H3C 公司为高校开发的自助网络服务系统。H3C 校园网自助服务系统 flexFileUpload 接口存在任意文件上传漏洞，攻击者可利用该漏洞上传恶意文件，获得服务器权限。  
  
**漏洞危害：**  
  
攻击者可利用该漏洞上传恶意文件，获得服务器权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单进行验证，并将上传文件保存在非 Web 可访问的目录中。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"H3C 校园网自助服务系统" 对潜在可能目标进行搜索，共得到1581条IP历史记录。主要分布在中国、巴西等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22H3C%20%E6%A0%A1%E5%9B%AD%E7%BD%91%E8%87%AA%E5%8A%A9%E6%9C%8D%E5%8A%A1%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I73UCFrVGaLomP8g3rlq8prKibx6YNEtqITl6EFTwpzsv8QHlWO8RfHfg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I75Pgm7FFTqich9QeKAPB1xkh6ARib85uibldKovMaI0dcv1MJ4VELQGRIQ/640?wx_fmt=png&from=appmsg "")  
  
  
3、万户 ezOffice rhinoscriptengineservice 远程代码执行  
  
**发布时间：**  
2024-02-26  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
万户 ezOFFICE 是一款 OA 办公系统。万户 ezOFFICE rhinoscriptengineservice接口存在远程代码执行漏洞。未经授权的攻击者可以利用此漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的攻击者可以利用此漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，限制访问和过滤用户输入可帮助减少风险，建议在服务器配置中禁用实体解析以及合理设置应用程序或服务的权限。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"wanhu" 对潜在可能目标进行搜索，共得到788条IP历史记录。主要分布在中国吉林、北京等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22wanhu%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I77ayibiazSBqKLZSDxZ0HfxMduiak3SrBH72OIlIaNUJw1qT5YVWzcRGBA/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7fCnUG2icGz8K72UkuZdU8UReAleJMZEkcbw9RjmjkbsicxCsiaUicKhPiaw/640?wx_fmt=png&from=appmsg "")  
  
  
4、宏景人力系统 DisplayFiles 任意文件读取  
  
**发布时间：**2024-02-27  
  
******漏洞等级：**高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
宏景人力资源管理系统是一款由宏景软件研发的系统。宏景人力系统 DisplayFiles 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，并对相关路径添加访问控制策略，防止出现任意文件读取。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"宏景 HCM" 对潜在可能目标进行搜索，共得到1549条IP历史记录。主要分布在中国、英国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22%E5%AE%8F%E6%99%AF%20HCM%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7N72Sgp7JsuSLT8JH9AIEV9pWRKgj95Y6cbEcC5woMpWU2VOhicpyHWw/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7ibGyUn8S3uvVmib8WBciaUu9gS5voDNJEVCQOTJYMZyRiaIZwGSPIwgyqw/640?wx_fmt=png&from=appmsg "")  
  
  
5、SolarView Compact texteditor.php 任意文件读取  
  
**发布时间：**2024-02-22  
  
**漏洞等级：**  
高危  
  
**漏洞来源：**  
创宇安全智脑  
  
**漏洞描述：**  
  
SolarView Compact是日本Contec公司的一个应用系统，提供光伏发电测量。SolarView Compact系统 texteditor.php 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，并严格限制文件读取权限。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"SolarView Compact" 对潜在可能目标进行搜索，共得到12744条IP历史记录。主要分布在日本、中国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22SolarView%20Compact%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7ZRY4FIS2PeY9JwAnhG764IjIbwia0m42uUqo18iaFzE7xWSXshiag6Qpg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7kaCgUwrrgFJonLw2A5h7Ydrm4qKvJd4Fudhot7ibVmSrCibsczBj8WTw/640?wx_fmt=png&from=appmsg "")  
  
  
6、广联达 Linkworks getalldata 信息泄露  
  
**发布时间：**2024-02-26  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
广联达 Linkworks是一种用于协同办公和项目管理的软件工具。广联达 Linkworks 存在信息泄露漏洞。未经授权的远程攻击者可以利用该漏洞，获取敏感信息。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，获取敏感信息。  
  
**建议解决方案：**  
  
及时更新至最新版本，实施严格的访问控制机制，确保只有授权的用户或角色能够访问和处理敏感数据。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"广联达 Linkworks" 对潜在可能目标进行搜索，共得到6215条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22%E5%B9%BF%E8%81%94%E8%BE%BE%20Linkworks%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7eXwEHpknAjK6naSHnHnvnhfh7hYMPfI9yudfiaqE5BUUnVvOnqpKBYg/640?wx_fmt=png&from=appmsg "")  
  
区域分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7LPntnyibyaCBmXBAibTXoS8TY65KDbqOEdBdtCx2233JFk5ibGqW6t6YQ/640?wx_fmt=png&from=appmsg "")  
  
  
7、金蝶云星空 ServiceGateway 反序列化远程代码执行  
  
**发布时间：**2024-02-23  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
金蝶云星空（ERP）是一款基于云计算、大数据、社交、人工智能、物联网等前沿技术研发的新一代战略性企业管理软件，为企业提供财务管理、供应链管理以及业务流程管理等一体化解决方案。金蝶云星空 ServiceGateway 接口存在反序列化远程代码执行漏洞。恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
恶意攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用 Web 应用程序防火墙等安全工具来检测和阻止已知攻击模式，防止漏洞被利用。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"金蝶云星空" 对潜在可能目标进行搜索，共得到8080条IP历史记录。主要分布在中国、新加坡等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22%E9%87%91%E8%9D%B6%E4%BA%91%E6%98%9F%E7%A9%BA%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7zzKkx1YFw6y7on9XKCk8k2FSPlxiamgSLXNa7uaZwpMqBm5uakznDeg/640?wx_fmt=png&from=appmsg "")  
  
区域分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7bXSvvm5BygPV3k23YBt6gWAF2hg52kP7zTwtJ73dBtdgrzX9kqyic5A/640?wx_fmt=png&from=appmsg "")  
  
  
8、WordPress Bricks Builder <= 1.9.6 远程代码执行（CVE-2024-25600）  
  
**发布时间：**2024-02-23  
  
**漏洞等级：**高危  
  
**漏洞来源：**  
  
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25600  
  
**漏洞描述：**  
  
WordPress 默认配置安装的 Brick Builder 主题在1.9.6及以下版本中存在远程代码执行漏洞。未经授权的攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**漏洞危害：**  
  
未经授权的攻击者可以利用该漏洞远程执行任意代码，获取系统权限。  
  
**建议解决方案：**  
  
更新版本到1.9.6以上，确保使用时进行输入验证，以防止参数中存在恶意的代码执行语句。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"WordPress Bricks Builder plugin" 对潜在可能目标进行搜索，共得到23556条IP历史记录。主要分布在美国、德国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22WordPress%20Bricks%20Builder%20plugin%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7NY9iaS0cYTdNqWo1XXa9WXApvkfPUBWWzcZ6Bd8zD74CCX5adoz6VpQ/640?wx_fmt=png&from=appmsg "")  
  
区域分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7c1DMDiagoWKXRaxILhX9ZRW4GZHRwZz34yEDjjP1TeRtGHXdSnvXzhg/640?wx_fmt=png&from=appmsg "")  
  
  
9、litemall 默认口令  
  
**发布时间：**2024-02-26  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
litemall是一个简单的商场系统，基于现有的开源项目，重新实现一个完整的前后端项目，包含小程序客户端、移动客户端和网页管理端。litemall 存在默认口令漏洞（admin123/admin123、mall123/mall123、  
  
promotion123/promotion123）。未修改默认密码的情况下，攻击者可以利用默认口令登录系统，获取系统敏感信息。  
  
**漏洞危害：**  
  
未修改默认密码的情况下，攻击者可以利用默认口令登录系统，获取系统敏感信息。  
  
**建议解决方案：**  
  
及时更改默认口令，使用字母大小写、数字、特殊符号的8位以上复杂密码。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"litemall" 对潜在可能目标进行搜索，共得到5129条IP历史记录。主要分布在中国、美国等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22litemall%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7nIBSPug246CMWspRkQPJGokLee6Kw00fgfgyQD3lpalDxdSYPf4hXQ/640?wx_fmt=png&from=appmsg "")  
  
区域分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7j9ft86FXvHicAwR3YZOuz6xnwcGc9bwSibmo1HYWlgoW50sLJwiaic5FFA/640?wx_fmt=png&from=appmsg "")  
  
  
10、通天星 CMSV6  
  
StandardReportMediaAction_getImage.action 任意文件读取  
  
**发布时间：**2024-02-26  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
通天星 CMSV6 平台是基于车辆位置信息服务及车辆视频实时传输服务为基础的创新技术及开放运营理念的平台。CMSV6 平台的  
  
StandardReportMediaAction_getImage.action 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，并严格限制文件读取权限。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"通天星 CMSV6" 对潜在可能目标进行搜索，共得到13212条IP历史记录。主要分布在中国、俄罗斯等国家。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22%E9%80%9A%E5%A4%A9%E6%98%9F%20CMSV6%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7ichWVxINLv1Ma1C5A7UJJfQPnchicotO1Guuu1laovIhQvbXhPsW8iaqA/640?wx_fmt=png&from=appmsg "")  
  
区域分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7j5jDia0F3ehic1nGo5TjcTojwleoK4MuUzzkpXiaGM2VicobiaTRsA0BxSQ/640?wx_fmt=png&from=appmsg "")  
  
  
11、易宝 OA DownloadFile 任意文件读取  
  
**发布时间：**2024-02-22  
  
**漏洞等级：**高危  
  
**漏洞来源：**创宇安全智脑  
  
**漏洞描述：**  
  
易宝 OA 系统是一款专门为企业和机构的日常办公工作提供服务的综合性软件平台。易宝 OA DownloadFile 接口存在任意文件读取漏洞。未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**漏洞危害：**  
  
未经授权的远程攻击者可以利用该漏洞，造成敏感信息泄露。  
  
**建议解决方案：**  
  
及时更新至最新版本，使用白名单限定访问文件的路径、名称及后缀名，并严格限制文件读取权限。  
  
**影响范围：**  
  
根据ZoomEye网络空间搜索引擎关键字 app:"易宝 OA" 对潜在可能目标进行搜索，共得到4133条IP历史记录。主要分布在中国广东、江苏等地。（ZoomEye搜索链接：  
  
https://www.zoomeye.org/searchResult?q=app%3A%22%E6%98%93%E5%AE%9D%20OA%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7kewiazz8XRgmSs8zOugLkKDFc4kpiauOTc0BXzRNuRw6RiaCLIgsNyR6w/640?wx_fmt=png&from=appmsg "")  
  
区域分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7gUQKyqjK8nGibppTZvZsj5a2xlAf6ae1Jt0icbX9bC2N22Oiamc189iahg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0xbpEWu0ry8v4kmFTkOq7I7vQ4r86kCqpjqhZCQVsudz9heq6FZm9UJLicV8S7K2HuLc0wnjKCpia8A/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
  
