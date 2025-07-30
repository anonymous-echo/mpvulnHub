> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492478&idx=1&sn=f7c44f86be38638134d679e6fb3b8ffd

#  ChkApi - API漏洞安全检测自动化工具、解析Swagger规范Bypass未授权检测等|漏洞探测  
0x727  渗透安全HackTwo   2025-06-17 16:01  
  
0x01 工具介绍  
  
  
ChkApi一款   
API 漏洞检测工具。支持提取网页 JS 和静态地址，解析 Swagger 规范，自动发现 API 接口及 Base URL。通过 Fuzz 测试、无参/有参请求及多种 Bypass 技术，检测未授权访问、远程命令执行等漏洞。结果以文本、Excel 存储，助力甲方安全人员巡检网站资产，发现敏感信息泄漏及潜在漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaO9w85Sp165hpnBP2T9jDDibIZGRmrPrJS5LKoeJ9lXRu6mLwiaHUZcUw/640?wx_fmt=png&from=appmsg "")  
  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
工具特点  
  
功能：通过提取自动加载和静态地址中的JS和页面内容，解析Webpack打包和使用正则匹配技术，发现API接口及Base URL。针对提取的接口，通过Fuzz测试、无参和有参请求三种方式验证接口响应，进一步智能提取参数并对其进行动态测试。支持各版本Swagger解析，自动识别危险接口，结合十余种Bypass技术绕过常见限制，全面挖掘未授权访问、远程命令执行、文件上传等漏洞。所有数据统一存储至文本、Excel中，重点关注接口响应的差异性和敏感信息泄漏情况，为漏洞发现提供数据支持。  
## API安全实践架构方案  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaWYj4XibnY6DdKsg3UKA19nKSXrXlAIpwoxzxsSapmC49hKmaHmzUKhA/640?wx_fmt=png&from=appmsg "")  
## API安全实践架构方案  
## 1.访问目标地址提取出自动加载的JS地址和静态地址  
  
获取JS地址有如下三种方式——加载当前域JS、加载CDN JS、加载其它域JS。  
  
(1) 加载的当前域JS：访问的URL地址为  

```
https://xxx.domain.com，该URL加载了当前域的JS（https://xxx.domain.com/js/yyy.js）。
```

  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaMGojOrPHGupWVyoevadib8NerORXdMMdvdZ2YWlVlmr3y76aSMLF7gw/640?wx_fmt=jpeg&from=appmsg "")  
  
(2) 加载的CDN JS：访问的URL地址为  

```
https://xxx.domain.com，该URL加载了CDN的JS（https://xxxcdn.com/js/yyy.js）。
```

  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiabQvHVPFic2YdgRXibgqgaoS1uSXAXD2mBIiaOPKLE5pctr99ZlkcbNicTg/640?wx_fmt=jpeg&from=appmsg "")  
  
(3) 加载的其他域JS：访问的URL地址为  

```
https://xxx.domain.com，该URL加载了其它域的JS（https://xxx.domain.com:8080/js/yyy.js）。
```

  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiatCQicqibPKVwBaduicTgIFc1rMsylueKcicEJPibt2oX4FBC7y9RCqIGsPg/640?wx_fmt=jpeg&from=appmsg "")  
  
(4) 静态地址：访问的URL地址为  

```
https://xxx.domain.com，该URL地址加载了静态地址（https://xxx.domain.com/path/zzz.html）。
提取静态地址的目的是在于全面获取目标网站的所有业务功能页面，确保不遗漏任何相关接口。
```

  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Diac6CeLN1OWV7V9vGvyrPnLuAVMFWg39b8eqU8A7jBR4TFnkX5CvAZBw/640?wx_fmt=jpeg&from=appmsg "")  
  
**2.提取网页未自动加载的JS地址**  
  
请求上述步骤获取到的JS地址，通过正则匹配语法，提取出在网页源码里的JS地址。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Diaocn6DsBQ40Dy5iaiagjibp1oLjrcmLXekIAPNqXibbGoMQXc6qkCUEdYXA/640?wx_fmt=jpeg&from=appmsg "")  
  
请求上述步骤获取到的静态地址，通过正则匹配语法，提取出在网页源码里的JS地址。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaVibsZicR5FZYhnwXX41ydbkia0QdvK3S4wlpsqpcJJKV7oib2q42jbuvBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**3.从webpack（JavaScript 应用程序的模块打包工具）提取JS地址**  
  
下图就是通过webpack打包JS地址的效果，实际上其中一个JS地址为/static/js/chunk-60893c6c.6867bfa5.js，因此需要通过正则语法精确提取出红框里的内容，并拼接成完整的JS地址。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiagqIKfLbgT5D0QvOTuvZ2BNY4MUlT0zP3XWTRKyZrgiaLQ1ZDPwwsNHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**4.Base URL发现**  
  
Base URL 可以理解为每个微服务的服务名称。在许多微服务架构的系统中，每个微服务都包含着大量的 API 接口，因此寻找 API 接口的关键之一是确定正确的微服务名称。  
  
微服务名称通常体现在 URL 地址的不同路径中，这个路径我称之为 Base URL。  
  
寻找Base URL有两种方式——自动加载的URL地址里就有Base URL、自动加载的API接口里提取出Base URL。  
  
(1) 自动加载的URL地址里就有Base URL：访问的URL地址为  

```
https://xxx.domain.com
```

  
该URL地址自动加载了地址（https://xxx.domain.com/authControl）那么可以认为authControl就是Base URL。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Diat288dEjYOs1JFxOzaJUohct7IBf8O4N7Po9JCv7LI2LUtq9LGYCHVQ/640?wx_fmt=jpeg&from=appmsg "")  
  
(2) 自动加载的API接口里提取出Base URL：访问的URL地址为  

```
https://xxx.domain.com
```

  
该URL地址自动加载了某API接口（https://xxx.domain.com/ophApi/checkCode/getCheckCode），在后续的API接口提取步骤中如果发现某API接口是/checkCode/getCheckCode，那么就会将ophApi当作Base URL。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaYpp1bO7zfpibt3jHVuHjcNY4Youib6qREJ4cFnibmMK0X1yL71rVRedew/640?wx_fmt=jpeg&from=appmsg "")  
  
**5.API接口的提取和Fuzz**  
  
(1) 请求上述所有的 JS 地址，并通过全面的正则表达式规则提取出 API 接口。例如，下图所示的 API 接口“/service/getFile?filePath=”。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaqB8tCJSdibTEM6TJBn7jCanz5JE11CC482zkaZS2wDILSno92cpQ8Pw/640?wx_fmt=jpeg&from=appmsg "")  
  
(2) 使用常见的API接口字典进行Fuzz测试，内置了一些常见的API接口字符串，以补充和完善API接口的提取过程。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiahVodLtGx8zvan7WHEZkQGFIiaTfp8RKfaKXqPUdBQqKbXEfqfLSoOfg/640?wx_fmt=jpeg&from=appmsg "")  
  
**6.Swagger各版本解析**  
  
支持解析各种版本的 Swagger 规范，能够精确提取所有 API 接口、请求方式、参数名称和参数类型。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaFiaMiccyUPPoFZMs8D3dHojROI3YWOzd0GibyKC6fHroVdiaD1NkcOKy0A/640?wx_fmt=jpeg&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaVWoQ5XLeEr5A9KCgIicIFAmWqUWYKiaLIVFEm2Dicm8DTNvEuzpDxzfHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**7.过滤危险接口**  
  
有些 API 接口可能涉及删除或取消等业务操作，因此需要对这些接口进行过滤。内置了以下关键字来过滤危险接口。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaCxrkiaRW6hU0vI6HXoaYoMH8hhRcfRgVcfZVzGd7oibVlQstrXicXU8GQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Diaiblicib0C4ZD8Pyb7CRWjpUwicAsDVoPghEaibjV6azVPcYCEjOXibNRXoAQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**8、无参三种形式请求所有API接口**  
  
上述步骤已提取出所有API接口，并通过 GET、POST DATA 和 POST JSON 三种请求方式逐一请求这些接口，保存每个接口的响应包内容。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaWN57BcDHRJnlFjf7lHzBFtPVjQu418vkDShkIekwVWGjofhHZHCdOw/640?wx_fmt=jpeg&from=appmsg "")  
  
**9.智能提取参数**  
  
从无参三种请求形式保存的 API 接口响应包中提取参数，具体包括以下三种情况：  
  
(1) 提取响应包内容中的 key 作为参数：  
  
如果响应包包含字段名，这些字段名将被提取为参数。例如，提取出 id 和 branchCollegeName。{"code":0,"msg":"success","data":[{"id":"xxxxxx","branchCollegeName":"xxxxxxxx"}]}  
  
(2) 提取 key 为 param 或 parameter时所对应的 value 作为参数：例如，提取出 imageId。  
  
{"code":200,"data":{"param":"imageId"}}  
  
(3) 提取响应包内容报错时，错误信息中提示缺失的内容作为参数：例如，提取出 types 或 accountId。  
  
{"code":1,"msg":"Required List parameter 'types' is not present","data":null}  
  
{"code":500,"msg":"accountId不能为空"}  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiampALEMciatv60HpS9iaJ24PxOK6R9icu3ichJBKZlL0C70iaqhJQiaHoMuvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
如下是提取出的参数名列表  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiatSubicictxZvawrP0uI93skFusEkF9Y1Ng0JQNVIC9CvuJ63da4JWPEg/640?wx_fmt=jpeg&from=appmsg "")  
  
**10.有参三种形式请求所有API接口**  
  
从上述步骤中整理出所有参数名称后，再次通过 GET、POST DATA 和 POST JSON 三种请求方式，携带这些参数逐一请求所有 API 接口，并保存每个接口的响应包内容。![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaMq4yicxYrHc92o8Miciba0deDHQfibJpicFcORl3cpFOk1xWm1rLS2qwI7A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Dia9Bsdxrnhlib42HKltgQ8n2CicFNY7bTiatyU2iaJDsAptePvRHXSuzTO7Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaUYNHDgcvH46flVynicto38y3TdktenDAAaWicr8E4hpUaPCDQvNCm2XA/640?wx_fmt=jpeg&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiauuTZ7xfniatX4U22qck2pu9KwTal1WyicFR6zr9jicUSuxnUJJjcIMHLg/640?wx_fmt=jpeg&from=appmsg "")  
  
**11.Bypass测试API接口**  
  
对于返回状态码 301、302、401、404 等或者响应包为空的 API 接口，内置了十多种绕过方法（Bypass 技术）进行再次测试。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaWiaibLJw2V1dIUnqsWvibbaJDXvvXGgak0xCVvMtYEzcsq2ezWLD1QqFg/640?wx_fmt=jpeg&from=appmsg "")  
### 数据整理  
### 在整个方案架构设计中，设置了三种数据存储方式，分别为文本文件（txt）、电子表格（Excel）和数据库（MySQL）。此项目为了易用，移除了Mysql存储。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Dia2gwvykv9mZGSIl5nQSm95AhBVjCNxlmGvqtxKdoHhKZcUibpIkcHKSg/640?wx_fmt=jpeg&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaWdUnPpFoVSeG6jGZACgeloajucsGAMMaribvkCoicyUpsKVYibhtLHCxw/640?wx_fmt=jpeg&from=appmsg "")  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaBFBP0NOcibXicq6OaIN1SwG9w433FQ7HzG686tvjDvttb6s3ibTJvq6zw/640?wx_fmt=jpeg&from=appmsg "")  
  
下图展示了数据库中存储的“参数”表。其中，parameter字段表示提取出来的参数名。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaoVhWgrkt0IREjpd0cIthWR2AyeIEYQukCrx6ibEN3VOCrlZyBKeu1gQ/640?wx_fmt=jpeg&from=appmsg "")  
  
下图展示了数据库中存储的“无参和有参三种请求方式结果”表。其中，api_url 字段表示 API 接口地址，method 字段表示请求方式，包括 GET、POST DATA 和 POST JSON 三种方式。parameter 字段表示请求 API 接口时携带的参数。res_type 字段表示响应包的返回格式，code 字段表示响应状态码，length 字段表示响应包内容的长度。  
  
这张表需要特别关注，因为在后续的运营过程中，通过分析这些数据可以发现大量 Web 漏洞。举例说明：  
  
寻找RCE漏洞：在api_url和parameter字段模糊匹配ping、cmd、command等关键词。  
  
寻找URL跳转或者SSRF漏洞：模糊匹配url、ip等关键词。  
  
寻找任意文件上传或者读取漏洞：模糊匹配upload、download、read、file等关键词。  
  
寻找未授权访问漏洞：模糊匹配get、config等关键词。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiavDgKl7DfF9MUY13AcqU3S80wPJTic3pntp7LnRYO2bRJKtqgIIZbk2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
下图展示了数据库中存储的“响应包差异化”表。其中，content_hash 字段表示响应包内容的哈希值，num 字段表示该哈希值出现的次数，length 字段表示对应响应包内容的长度，file_path 字段表示响应包保存的文件路径。  
  
添加响应包差异化功能的原因在于，当测试 API 接口时未携带凭证，许多返回结果会是相同的提示缺少凭证的内容。通过此方法，可以快速过滤掉大量重复的响应包，从而降低运营成本。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Dia9hBTNxkibjGibic6btdicoKJ20hYYxbdxk81vHibLZPTicTTTZxekibhThoaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
下图展示了数据库中存储的“敏感信息泄漏”表，可以看到其中包含泄漏的敏感信息，如 JDBC 连接语句、账号密码、私钥、凭证，以及各种云平台的 AKSK 等。![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Dia8rhCCichPn4U52iahHdNic1qFo9WF7EUEKqR2K1newL0J3ia1UBBh8xkuQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2Dia05HfmRFyISt8QFGQbiasnYN47WGybdGzyLa80HkuOIRNHibF3Wibq1M3g/640?wx_fmt=jpeg&from=appmsg "")  
###   
  
0x03更新说明  
  

```
暂无
```

  
  
0x04 使用介绍  
  
📦安装  
  
为了避免踩坑,建议安装在如下环境中  
  
python3.8及以上，建议VPS环境是ubuntu20，默认是python3.8。  
  
需要安装chromedriver，在build.sh里内置了安装命令（默认是Linux版本的，如果是Mac电脑则自己安装下）  

```
chmod 777 build.sh
./build.sh
```

  

```
 python3 ChkApi.py -h
```

  
![image-20250120153217014](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7HEib0jVOOdl3IAia3o1ia2DiaJrIfYMefvyCbrReLRBToOOp44g8pcd1S7AO19G08NZAo7FU8R21GWQ/640?wx_fmt=png&from=appmsg "")  
## 使用方法  
<table><thead><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><th align="left" style="box-sizing: border-box;padding: 6px 13px;font-weight: 600;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">语法</span></span></section></th><th align="left" style="box-sizing: border-box;padding: 6px 13px;font-weight: 600;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">功能</span></span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">python3 ChkApi.py -u http://www.aaa.com</span></span></section></td><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">对单一url进行扫描</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(246, 248, 250);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">python3 ChkApi.py -u http://www.aaa.com -c &#34;xxxxxxxxxx&#34;</span></span></section></td><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">携带cookies对单一url进行扫描</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">python3 ChkApi.py -f url.txt</span></span></section></td><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">对文件里的网站进行扫描</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(246, 248, 250);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">python3 ChkApi.py -u http://www.aaa.com --chrome off</span></span></section></td><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">off关闭chromedriver，默认是on</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(255, 255, 255);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">python3 ChkApi.py -u http://www.aaa.com --at 1</span></span></section></td><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">0 收集+探测、1 收集， 默认是0</span></span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(246, 248, 250);border-top: 0.666667px solid rgba(209, 217, 224, 0.7);"><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">python3 ChkApi.py -u http://www.aaa.com --na 1</span></span></section></td><td align="left" style="box-sizing: border-box;padding: 6px 13px;border-color: rgb(209, 217, 224);border-style: solid;border-width: 0.666667px;border-image: none 100% / 1 / 0 stretch;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">不扫描API接口漏洞，1不扫描，0扫描，默认是0</span></span></section></td></tr></tbody></table>##   
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFShow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1800+多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250618获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
