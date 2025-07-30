#  Feroxbuster-高效发现隐藏路径和漏洞（详细教程）   
原创 zangcc  Eureka安全团队   2024-11-26 09:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/7GhZKSNyIWW7hOPGVGAFdB0LicgBD9QCTEVRdLGXklRmwEsxuNVbR5ibwLzxicafIHsW1U9WpV0Mznib50aAn0mqSQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**点击上方**  
**蓝字**  
**关注我们**  
  
## 0x01 feroxbuster的安装  
  
文末抽奖送书：《Java网络爬虫精解与实践》89💰 x2  
  
官网下载地址，能适配的系统很全，找到自己系统的版本下载下来就可以了。  
```
https://github.com/epi052/feroxbuster/releases
```  
  
解压之后，给二进制文件赋予可执行权限：  
```
chmod +x feroxbuster
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibFxo8sZgWUtyaF8e6vCpwB8ya6rc4QvmujpQw8otNQSCbdJdJrPUKZQ/640?wx_fmt=png&from=appmsg "")  
  
我看网上绝大部分关于 feroxbuster的文章都非常的划水，相关的文章在网上乱七八糟。其实在真实的使用场景里，会有很多疑问和坑点。  
  
目录扫描-是我司安全建设的重要一环（相信所有 有安全部的公司都是🙏），想要覆盖面更广一些，就需要多个目录扫描工具的结果对比，由于dirsearch的bug太多，所以找了同样拥有出色目录扫描能力的feroxbuster和httpx，其中feroxbuster（6k stars）和httpx（13.3k stars）这两个项目都在github上非常的活跃，更新迭代很快，这次趁着有空梳理一下feroxbuster的详细使用方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibjmXSWwLrGgOuX3picQkULCTwcLe5K4vtu2ibzBlaaRynTa255IywuWXQ/640?wx_fmt=png&from=appmsg "")  
  
  
## 0x02 扫描模式-单个or多个目标  
  
2.1 单个目标的扫描：  
```
./feroxbuster -u http://xxx.com -w /path/to/wordlist -o  result.txt
```  
  
-u 被扫描的目标url  
  
-w 字典的路径  
  
-o 输出结果的文件  
  
  
2.2 多个目标的扫描：  
```
cat targets.txt  | ./feroxbuster -w /path/to/wordlist --stdin  -o  result.txt
```  
  
targets：多个url的文件，以行隔开  
  
--stdin：从标准输入（STDIN）读取 多个URL，feroxbuster 会等待从 STDIN 接收 URL，而不是从命令行参数中获取。将一个文件或另一个命令的输出直接作为输入传递给 feroxbuster。  
  
## 0x03 ferox-config.toml配置  
  
通过修改配置文件的方式来代替繁琐的命令行参数。  
  
通过--help可以查看所有的参数，有非常的多，如果相同的扫描但是每次都要输入繁琐的参数，那就有点麻烦了，所以我非常推荐用配置文件的方式来配置扫描。  
```
https://epi052.github.io/feroxbuster-docs/docs/configuration/ferox-config-toml/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibxMyibGkibTpnWn4jpR2AdWjqm4fSmXsr9bpyZcQmcb7BOft9fJpzcvUA/640?wx_fmt=png&from=appmsg "")  
  
配置文件存放的位置也是有讲究的，位置在每个系统中的位置都有一个固定的。  
  
官方给出的例子（这里的Bob指的是你系统的用户名，根据实际的用户名来修改）：  
```
Linux:/home/bob/.config/feroxbuster/ferox-config.toml

MacOs: /Users/bob/Library/Application Support/feroxbuster/ferox-config.toml

Windows: C:\Users\Bob\AppData\Roaming\feroxbuster/ferox-config.toml
```  
  
  
刚开始是没有这个配置文件的，所以需要自己在这个路径下创建一个/ferox-config.toml  
文件，然后将官方给出的配置文件复制粘贴进去：  
```
# Example configuration for feroxbuster
#
# If you wish to provide persistent settings to feroxbuster, rename this file to ferox-config.toml and make sure
# it resides in the same directory as the feroxbuster binary.
#
# After that, uncomment any line to override the default value provided by the binary itself.
#
# Any setting used here can be overridden by the corresponding command line option/argument
#
# wordlist = "/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
# status_codes = [200, 500]
# filter_status = [301]
# threads = 1
# timeout = 5
# proxy = "http://127.0.0.1:8080"
# replay_proxy = "http://127.0.0.1:8081"
# replay_codes = [200, 302]
# verbosity = 1
# parallel = 8
# scan_limit = 6
# rate_limit = 250
# quiet = true
# silent = true
# auto_tune = true
# auto_bail = true
# json = true
# output = "/targets/ellingson_mineral_company/gibson.txt"
# debug_log = "/var/log/find-the-derp.log"
# user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
# random_agent = false
# redirects = true
# insecure = true
# collect_words = true
# collect_backups = true
# collect_extensions = true
# extensions = ["php", "html"]
# dont_collect = ["png", "gif", "jpg", "jpeg"]
# methods = ["GET", "POST"]
# data = [11, 12, 13, 14, 15]
# url_denylist = ["http://dont-scan.me", "https://also-not.me"]
# regex_denylist = ["/deny.*"]
# no_recursion = true
# add_slash = true
# stdin = true
# dont_filter = true
# extract_links = true
# depth = 1
# limit_bars = 3
# force_recursion = true
# filter_size = [5174]
# filter_regex = ["^ignore me$"]
# filter_similar = ["https://somesite.com/soft404"]
# filter_word_count = [993]
# filter_line_count = [35, 36]
# queries = [["name","value"], ["rick", "astley"]]
# save_state = false
# time_limit = "10m"
# server_certs = ["/some/cert.pem", "/some/other/cert.pem"]
# client_cert = "/some/client/cert.pem"
# client_key = "/some/client/key.pem"
# request_file = "/some/raw/request/file"
# protocol = "http"
# scan_dir_listings = true


# headers can be specified on multiple lines or as an inline table
#
# inline example
# headers = {"stuff" = "things"}
#
# multi-line example
#   note: if multi-line is used, all key/value pairs under it belong to the headers table until the next table
#         is found or the end of the file is reached
#
# If you want to use [headers], UNCOMMENT the line below
# [headers]
# stuff = "things"
# more = "headers"
```  
  
  
这里提一个关键点！除了上述的默认系统路径，还有一个更简单更便捷的方式，那就是直接在可执行二进制文件的当前路径存放ferox-config.toml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibzIG3aNpgenZjicH6zcu2HtjUrD1xq38Yd6Jch9EL8eqqvqUDvGiaYPsQ/640?wx_fmt=png&from=appmsg "")  
  
放到这里配置文件也能生效，亲测可用！  
  
配置文件包含了所有的参数，把自己想修改的配置选项前面的#号去掉，然后修改对应的值就可以了。这里我推荐修改的地方有：  
```
#自定义的扫描字典文件

wordlist = "/home/ubuntu/tools/scanner_feroxbuster_dicc.txt"

#过滤的端口

filter_status = [404,429,403,500,301,302,401,400,503]

#线程数

threads = 20

timeout = 5

depth = 2

#字符数（字节数）：过滤

filter_size = [0]

#单词的数量过滤

filter_word_count = [0]

#按页面相似度过滤-根据与给定页面的相似性过滤响应

filter_similar = ["https://somesite.com/soft404"]
```  
  
重点说一下**filter_similar**  
，非常的强大。  
  
它通过比较扫描过程中发现的页面响应内容，自动识别并排除（例如错误页面或占位符页面）相似的结果。这种过滤基于页面的相似性算法，有助于避免冗余结果，从而提高扫描效率和准确性。  
  
例如，如果某个错误页面响应的格式和内容固定，filter_similar 会将这些页面从结果中移除，使得你专注于更有意义的发现。这种功能在扫描过程中尤为重要，特别是当服务器返回大量通用响应时，可以显著减少不必要的误报。（用的是Simhash算法）  
  
filter-similar的原理-官方参考链接：  
```
https://epi052.github.io/feroxbuster-docs/docs/examples/filter-similar/
```  
  
## 0x04 实践到企业安全建设中  
  
这里为了隐私性，我就以百度为例，做了个简单的测试，只扫描了10条。  
  
写一个钉钉机器人脚本，工具定时循环扫描，将扫描结果与上一次的做对比，将新增的推送到钉钉；也可以不做对比，直接将新一轮的扫描结果直接推送也可以。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaib4Fhh2ZaDxkdX44az9iaYSRLAYYBwx3ypfb9zQEbicwsFYURPA1GaNadA/640?wx_fmt=png&from=appmsg "")  
  
扫描结果的每个字母，官方也给出了含义。  
l:行数    
w:单词数   
c:响应体中的字符（字节）数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibqbURgmB7iaCmE9K6TYzwQkOgEaS6p03zZL5516ECYaaicbOYpwgRQIBg/640?wx_fmt=png&from=appmsg "")  
  
  
这里还有一个点，因为feroxbuster的扫描结果报告中，会在报告文件前有一大段的  
Configuration{...}  
  
所以要写一个正则来匹配这一段的文本，然后将其抹除。正则我也贴出来给大家，可以直接使用👀：  
```
Configuration\s*\{(?:[^{}]*|\{(?:[^{}]*|\{[^{}]*\})*\})*\}
```  
  
该有的配置和使用方法都满足甲方安全建设和红队渗透信息收集的使用场景，可以使用 Feroxbuster 高效发现隐藏路径和漏洞。  
  
  
## 0x05 《Java网络爬虫精解与实践》  
  
《Java网络爬虫精解与实践》官方正版实体书 89元💰 x 2：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibCuRwykLA2zIPm6GPcibDNMArJGLx0NibIsbLAfQZmjO93XPAicbiadzsLA/640?wx_fmt=png&from=appmsg "")  
  
《Java网络爬虫精解与实践》全面而系统地介绍与网络爬虫程序相关的理论知识，并包含大量的实践操作案例。《Java网络爬虫精解与实践》共分为 8 章。第 1 章以自动化框架为基础，介绍网络爬虫程序的入门开发实践。第 2 章深入讲解网页内容的处理、解析技术和数据提取方法。第 3 章讨论验证码识别技术以及如何有效绕过验证码的策略。第 4 章涉及网络抓包技术及其对抗策略。第 5 章深入探讨 JavaScript 代码的混淆技术与逆向分析方法。第 6 章专注于移动端应用程序的数据爬取技术及相关逆向分析技术。第 7 章介绍构建分布式网络爬虫系统所需的关键技术。第 8 章通过实战案例，展示分布式网络爬虫系统设计与实现的思路。通过学习本书，读者将显著提升网络爬虫系统的设计与实现能力，并增强对网页代码及移动端应用程序代码的  
**逆向分析水平**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibCXdE0qfZib8d9fGR0gzAmNvryz8y74u9e6LNQKHJBW5BjDicScdOsv9g/640?wx_fmt=png&from=appmsg "")  
  
  
公众号内购买-5折优惠：  
  
  
参与条件：“  
点赞” 或者 “  
在看” 公众号任意一篇文章即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NPnzIJjReIdKzEv2ib8MTpiaibFmuldfhmHXkzqLTic9aL0pCibbyNK2AzyPVbAmtCIqVGx7dwiaBtPOh6w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
更多 >>  技术分享  
  
欢迎大家关注EureKaSec，无论是技术交流还是有兴趣加入我们团队，都欢迎随时联络沟通。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CibE0jlnugbX5SLGI9312kOrkH7gXIN5NPic75bQ8WbAFMEqvZiaQ0WSk4W9eYUfJJRzlMgibjic8mIGicMvjialoDgmQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NM9WYO94RZib7HaaibSibMic91gPq8qbxL1jdjlslceibTEgJaLzvA1QVIkJ1sdaLJpYRzyw25hVIlxNkw/640?wx_fmt=jpeg "")  
  
如有问题  
  
联系作者      
  
EureKaSec  
  
  
点个“在看”，挖洞必高危！  
  
人划线  
  
  
  
