#  好工具分享：Web漏洞fuzz神器 Arjun   
枇杷五星加强版  黑伞安全   2023-07-25 17:33  
  
# Arjun  
#### HTTP Parameter Discovery Suite  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8kQRhKfTlwCdoRRW4rOwxx96FzA7r86JcUpu4MKBC2llkt2icMkGlW2sbicg9ImqPIS6OjvZDShbpx/640?wx_fmt=svg "")  
 ![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8kQRhKfTlwCd3TeE8THhia4dcKK1Z2M83wL17sZOibgXpUUDGqsiaqXldpsNrYhXmicgtDBjvIO3g66d/640?wx_fmt=svg "")  
 ![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8kQRhKfTlwCdpg0lXGrSdsXAluPcbichkvTgichJufAibmib6O36g43oDVGhzUsCxQFsClCzRXVDf6Yt/640?wx_fmt=svg "")  
 ![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8kQRhKfTlwCdpDR5LuNxnmsj7yktNgUShAq2zX5dexDW3vibsNDt8p4zSlUyg0nydGvJeR4d2wQcx/640?wx_fmt=svg "")  
  
  
https://github.com/s0md3v/Arjun  
  
我在日常src挖掘中枇杷哥常用的参数fuzz工具，参数fuzz至少赚到了几K赏金，大家可以上手试试。原理大致就是参数二分法，可以抓包看一下就懂了。  
  
  
### 扫描单个网址  
  
选项：-u  
  
针对单个 URL 运行 Arjun。  
```
arjun -u https://api.example.com/endpoint

```  
### 指定 HTTP 方法  
  
选项：-m  
  
GET  
Arjun默认  
查找方法参数。  
所有可用的方法有：GET/POST/JSON/XML  
```
arjun -u https://api.example.com/endpoint -m POST

```  
### 导入目标  
  
选项：-i  
  
Arjun 支持从 BurpSuite、简单文本文件和原始请求文件导入目标。  
Arjun 可以自动识别输入文件的类型，因此您只需指定路径即可。  
```
arjun -i targets.txt

```  
> 注意：  
在 Burp Suite 中导出项目时取消选中“base64”选项。  
  
### 导出结果  
  
选项：-oJ/-oB/-oT  
  
您可以使用相应的选项将结果导出到 BurpSuite 或 txt/JSON 文件。  
```
arjun -u https://api.example.com/endpoint -oJ result.json

```  
```
-oJ result.json
-oT result.txt
-oB 127.0.0.1:8080

```  
### 指定注入点  
  
Arjun默认可以在使用JSON  
或方法参数  
时检测指定位置的参数。XML  
所有可用的方法有：GET/POST/JSON/XML  
```
arjun -u https://api.example.com/endpoint -m JSON --include='{"root":{"a":"b",$arjun$}}'

```  
  
或者  
```
arjun -u https://api.example.com/endpoint -m XML --include='<?xml><root>$arjun$</root>'

```  
### 多线程  
  
选项：-t  
  
Arjun 默认使用 2 个线程，但您可以根据您的网络连接和目标限额调整其性能。  
```
arjun -u https://api.example.com/endpoint -t 10

```  
### 请求之间的延迟  
  
选项：-d  
  
您可以使用该选项延迟请求-d  
，但它也会将线程数设置为1  
。  
```
arjun  -u https://api.example.com/endpoint -d 2

```  
### 请求超时  
  
选项：-T  
  
您可以使用选项指定 HTTP 请求的超时时间-T  
，默认值为15  
。  
```
arjun  -u https://api.example.com/endpoint -T 10

```  
### 处理速率限制  
  
选项：--stable  
  
--stable  
将线程数设置为1  
并在请求之间引入 6 到 12 秒的随机延迟。  
```
arjun  -u https://api.example.com/endpoint --stable

```  
### 包括持久数据  
  
选项：--include  
  
假设您有一个 API 密钥，需要在每个请求中发送，为了告诉 Arjun 这样做，您可以使用--include  
以下选项：  
```
arjun  -u https://api.example.com/endpoint --include 'api_key=xxxxx'

```  
  
或者  
```
arjun  -u https://api.example.com/endpoint --include '{"api_key":"xxxxx"}'

```  
  
要包含多个参数，请使用&  
分隔它们或将它们作为有效的 JSON 对象传递。  
### 控制查询/块大小  
  
选项：-c  
  
默认情况下，Arjun 在请求中包含 500 个参数，有时可能会超出某些服务器的最大 URL 长度限制。-c  
您可以通过指定一次发送的参数数量  
来处理这种情况。  
```
arjun -u https://api.example.com/endpoint -c 250

```  
### 禁用重定向  
  
选项：--disable-redirects  
  
此开关将阻止 Arjun 跟踪目标 URL 上的重定向。  
建议仅当您知道自己在做什么时才使用它。  
```
arjun -u https://api.example.com/redirects_to_api2 --disable-redirects

```  
### 从被动源收集参数名称  
  
选项：--passive  
  
您可以从 CommonCrawl、Open Threat Exchange 和 WaybackMachine 收集域（而非子域）的参数名称，并检查它们是否存在于您的目标上。  
```
arjun https://api.example.com/endpoint --passive example.com

```  
  
如果您想使用目标 URL 中的域，请使用--passive -  
.   
它仅适用于单个目标。  
### 使用自定义 HTTP 标头  
  
选项：--headers  
  
您可以简单地从命令行添加自定义标头，按\n  
如下所示分隔：  
```
arjun -u https://api.example.com/endpoint --headers "Accept-Language: en-US\nCookie: null"

```  
  
  
使用--headers  
不带任何参数的选项将打开文本编辑器（默认为“nano”），您只需将 HTTP 标头粘贴到此处并按Ctrl + S  
保存即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGq9RvehwyNcvlcao0yOfVjZJW5c9rSarIjCgx2xclVphLtfpvAHjjLZbnStOCcOpISDQKCcUE3LFg/640?wx_fmt=png "")  
> 注意：  
 Arjun 使用nano  
提示的默认编辑器，但您可以通过调整 来更改它/core/prompt.py  
。  
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGq9RvehwyNcvlcao0yOfVjZxBYia28PZLYTGY1NbyXibbOndrQTADwmtBeENloRlF6R91CfJnGdZgPA/640?wx_fmt=png "")  
### What's Arjun?  
  
Arjun can find query parameters for URL endpoints. If you don't get what that means, it's okay, read along.  
  
Web applications use parameters (or queries) to accept user input, take the following example into consideration  
  
http://api.example.com/v1/userinfo?id=751634589  
  
This URL seems to load user information for a specific user id, but what if there exists a parameter named admin which when set to True makes the endpoint provide more information about the user?This is what Arjun does, it finds valid HTTP parameters with a huge default dictionary of 25,890 parameter names.  
  
The best part? It takes less than 10 seconds to go through this huge list while making just 50-60 requests to the target. Here's how.  
### Why Arjun?  
- Supports GET/POST/POST-JSON/POST-XML requests  
  
- Automatically handles rate limits and timeouts  
  
- Export results to: BurpSuite, text or JSON file  
  
- Import targets from: BurpSuite, text file or a raw request file  
  
- Can passively extract parameters from JS or 3 external sources  
  
### Installing Arjun  
  
You can install arjun with pip as following:  
```
pip3 install arjun

```  
  
or, by downloading this repository and running  
```
python3 setup.py install

```  
### How to use Arjun?  
  
A detailed usage guide is available on Usage section of the Wiki.  
  
Direct links to some basic options are given below:  
- Scan a single URL  
  
- Import targets  
  
- Export results  
  
- Use custom HTTP headers  
  
Optionally, you can use the --help argument to explore Arjun on your own.  
##### Credits  
  
The parameter names wordlist is created by extracting top parameter names from CommonCrawl dataset and merging best words from SecLists and param-miner wordlists into that.db/special.json wordlist is taken from data-payloads.  
  
  
