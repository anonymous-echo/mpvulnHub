#  D-Link Go-RT-AC750命令注入漏洞复现   
伯爵的信仰  看雪学苑   2023-08-11 18:01  
  
```
```  
  
  
前面的复现都是以CVE编号为主的复现，这次换个方式，以路由器型号为单位进行复现。本次复现的命令注入漏洞都是D-Link Go-RT-AC750中存在的漏洞，目前一共有五个：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1ic8LkOJnodURkkbmfvfpnqfTicyl0I4HYaIdUrm6RoL1tZYgG6iaOqCOA/640?wx_fmt=png "")  
  
  
```
```  
  
  
在对D-Link Go-RT-AC750命令注入漏洞复现前先了解一些背景知识，主要是CGI和UPnP。  
  
#### 2.1 CGI（Common Gateway Interface）通用网关接口  
  
  
CGI规定了Web服务器调用CGI程序的接口协议标准。Web服务器通过调用CGI程序实现和Web浏览器的交互, 即CGI程序接收Web浏览器发送给Web服务器的信息并进行处理, 将处理后的结果返回给Web服务器。组成CGI通信系统的是两部分：一部分是html页面，用于在浏览器上显示；另一部分则是运行在服务器上的CGI程序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S18w2PLFEw0zdztdXXlxSbK1FjMPEo9AQswJAsV20oE3W1JXlhJepq8A/640?wx_fmt=png "")  
  
通常情况下，服务器和CGI程序在Web环境变量的协作下，通过标准输入（stdin）和标准输出（stdout）来进行数据传递。以Go-RT-AC750的Web服务器工作流程为例：  
  
  
1.服务器接收到浏览器传来的URL，识别URL中指定的脚本，如xx.php或xx.cgi并将其交给cgibin解析处理。  
  
  
2.服务为CGI程序（cgibin）执行做准备，比如准备环境变量和相关参数。  
  
  
3.CGI程序（cgibin）读取标准输入和相关环境变量，执行相应处理，处理完后将结果由标准输出返回到服务器。  
  
  
4.服务器将收到的处理结果传回浏览器。  
  
  
CGI程序继承了系统的环境变量。CGI环境变量在CGI程序启动时初始化，在CGI程序结束时销毁。当CGI程序被HTTP服务器调用时，它的环境变量就会增加一些和HTTP服务相关的环境变量。下面是一些常见的和HTTP相关的环境变量（CGI程序使用getenv()  
函数获取环境变量，例如getenv("CONTENT_TYPE")  
）：  
####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1ibJVLYN7lhUOZbrCfWnWRAuwiaibgh0boUolFFjyVFc3Cewa7Mdiac5Riaw/640?wx_fmt=png "")  
  
#### 2.2 UPnP（Universal Plug and Play）通用即插即用  
  
  
UPnP是由微软提出的一种通用即插即用技术，后续联合英特尔等多家科技公司共同制定了UPnP标准。UPnP主要是为了实现在“零配置”的前提下在联网设备间能自动连接和协同工作。UPnP的协议栈结构图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1NdUoxT4deaJyPFdz5B0FqyYVqUiaaTLRaenHDooiaoibluf4RWO85K8nQ/640?wx_fmt=png "")  
  
  
UPnP协议体系结构中主要协议和规范包括：  
  
  
◆SSDP（Simple Service Discovery Protocol）简单服务发现协议，用于发现网络中的UPnP设备。  
  
  
◆GENA（Generic Event Notification Architecture）通用事件通知结构，用于及时通知状态变化。  
  
  
◆SOAP（Simple Object Access Protocol），简单对象访问协议，用于保证UPnP设备具有互操作能力。  
  
  
◆XML（Extensible Markup Language）可扩展标记语言，对设备和服务进行统一的描述。  
  
  
当加入一个新的UPnP设备时，工作流程如下：  
  
  
1.设备加入网络后通过设备寻址（addressing）就可自动获得IP地址；  
  
  
2.通过设备发现（discover）控制点就可知道网络上存在哪些设备；  
  
  
3.通过设备描述（description）控制点就可知道设备详细信息以及设备提供哪些服务；  
  
  
4.通过设备控制（control）控制点可以使用设备的服务；  
  
  
5.通过设备事件（event）就可以将其状态变化及时告诉给订阅的控制点；  
  
  
6.通过设备展示（presentation）控制点可以用浏览器察看设备状态和控制设备。  
  
  
通过上述六个步骤，UPnP设备可以做到在“零配置”的前提下提供联网设备之间的自动发现、自动声明、“直接”信息交换和互操作等功能，真正实现“设备即插即用”。  
  
  
这里只是给个简单介绍，具体实现细节请阅读UPnP官方文档，链接见参考文章。  
  
  
```
```  
  
  
使用binwalk解包，获取文件系统：  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1fE0TDGsUphl9f4LcK3tic3ibib2P5HDtjMSP555sHNk1borZgQ6gNia7DA/640?wx_fmt=png "")  
  
  
解包成功，浏览完文件系统中文件发现有telnetd，可用于漏洞验证：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1Fa6zTjCGASPicEAlDkYWXicOQOyne1TQIS6xOwtujgef2ruAaiaO0CJlQ/640?wx_fmt=png "")  
  
  
以调试方式模拟固件，以便分析过程中使用shell查看运行时相关信息：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1ajGhtcufQ9oR8Tl9CQbKyRAnwBYn7qfraCoonvPWLPqRZbC8bStAKA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1pjiaz2nxCnNsX4Bgy19pKoicFibiaIicK9uPrMdOZIP6nNBGMDUDyhyCA5g/640?wx_fmt=png "")  
  
  
模拟成功后扫描端口：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1h4xld46bPuGD4iaARQWglWoGe2HBybV0EwRq7vlpYHEubldfvAnVxbA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1e7es53aRAvzcZ1B7piamicwd2BcAVLxhavSXtVSJhXXLsJruKY8sa7gA/640?wx_fmt=png "")  
  
  
通过调试shell查看文件：/var/run/httpd.conf 可知49152  
是upnp服务端口。  
  
  
```
```  
####   
#### 4.1 漏洞分析  
  
  
根据漏洞披露的信息，这个漏洞和服务参数以及genacgi_main函数有关，查找字符串genacgi_main找到相关文件htdocs/cgibin：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1Mnd1M6Uck9IMuwhiaN4qpVSiaVqEAF6Bk8RFAGqSDZto2ImL5Y3qkLCw/640?wx_fmt=png "")  
  
  
将htdocs/cgibin拿到IDA中分析，并直接定位到函数genacgi_main，调用该函数的代码为：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1QdVMXWo585xm0ABQO6fAsic9IFOj0AoZc1lCSn3ics6r6gpvLLSbyRBw/640?wx_fmt=png "")  
  
  
在cgibin程序的main函数中判断是否为gena.cgi  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1KjaCx4Gd5AqM1j5ZtzgSrJsJ3KibjicojUmzialjibdlBRiaJcyjnWP53LA/640?wx_fmt=png "")  
  
  
genacgi_main函数的功能是：检查HTTP请求方法和判断URI中是否有?service=  
，若HTTP请求方法为SUBSCRIBE或UNSUBSCRIBE则调用对应的函数处理。当REQUEST_METHOD为SUBSCRIBE  
时，获取一些环境变量并使用sprintf函数拼接成字符串传入到xmldbc_ephp函数中处理：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S13Z3jWiaEem4ypaBXnLoQ6EVibMPA3fomb4kwKp1uOwPGHzHTEEDjkthg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1CxymVglWyVJ6r9ib6WRMYSKWEF5r7RRb0dldhFkbn3mib0ibh0mfDhT8Q/640?wx_fmt=png "")  
  
  
xmldbc_ephp函数将拼接的subscribe_string 通过/var/run/xmldb_sock传入到/htdocs/upnp/run.NOTIFY.php文件中进行处理并返回处理结果到服务器。subscrib_string的内容形式为：  
  
  
```
```  
  
  
  
查看/htdocs/upnp/run.NOTIFY.php文件内容：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S16PBBOyJgDh4zyFwKEwowbxdmdVcZyRdF0Fj2dP4FJ4tJvic0UmXbaXQ/640?wx_fmt=png "")  
  
  
查找文件中涉及的函数GENA_subscribe_new：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S17oDMBay8HGzicXwD0F7CszenH2DARg5WB8lecTicLebX0Nh0jrKtNAng/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1j9N4MibUZYU9NVrF5awc0EqzySnhIDG10iazCbPMB0qERDLPWWnd2reg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1cRLypLjibEJRNbmWCYSEpekiaAb1ibQ3w2PUdzDAPZiamLSc3CxS2fdhMw/640?wx_fmt=png "")  
  
  
综上可知漏洞点在fwrite(a, $shell_file, "rm -f ".$shell_file."\n");  
代码中的目的是为了执行rm -f shell_file命令删除shell_file文件，但shell_file可通过SUBSCRIBE传入的服务参数进行控制并且全程没有任何对服务参数的检查，从而可实现命令注入。  
  
#### 4.2 漏洞复现  
  
  
此漏洞涉及到的是UPnP的GENA（通用事件通知结构）相关内容,当设备服务状态发生变化时，会通过event通知控制点。控制点能收到通知的前提是要先订阅（SUBSCRIBE）该服务的指定event。订阅特定服务的事件的方法是：发送订阅消息到该服务的事件 URL。通过分析可知，此漏洞的触发条件是要路由器发送UPnP订阅服务的请求。根据UPnP官方文档可知订阅请求格式如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1hu0ibcb8xDjEuw62ZpIfzBiaMRZR8Ur2DaJNpGVib5k8j1y5rutA75sUw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S11twzzJyXQs0StmrlnZ9Ym6VoDKsNibukvKV4mVP9KJvB7c33iaOjF32Q/640?wx_fmt=png "")  
  
  
结合UPnP文档和/var/run/httpd.conf文件内容 可知要构造的subscriber的请求头如下：  
  
  
```
```  
  
  
  
Poc脚本执行后，成功取得shell：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1BXa1OkQrXzS4cefS4fMwPlsbSUicpSocIibC2duvppUCgKqgq55YLzPg/640?wx_fmt=png "")  
####   
#### 4.3 Poc  
  
  
```
```  
  
###   
###   
```
```  
####   
#### 5.1 漏洞分析  
  
  
根据漏洞披露的信息可知漏洞点和 service 参数以及 soapcgi_main 有关，在文件系统中查找soapcgi_main并定位到所在文件cgibin，将其拿到IDA中逆向分析，通过函数名查找，定位到soapcgi_main函数，调用该函数的代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1pKCebaIGrwtR6eouz82CzjRnpicqPwcmhWzYEkIOO6ibssKGbOUDxctw/640?wx_fmt=png "")  
  
  
soapcgi_main中关键代码如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1B9AS2pL5GVRIMfN1ibo8OsgYGclmaibt7wu1WyiaGbUFXPaPAFiadfAGpQ/640?wx_fmt=png "")  
  
  
这段代码是在获取与请求相关的环境变量，可获得的信息有：  
  
◆REQUEST_METHOD: POST  
  
◆CONTEXT_TYPE: text/xml  
  
◆REQUEST_URI：含?service=  
  
◆HTTP_SOAPACTION：含有“”，且“”中含有#  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1MvGibD30ia07LiaadRyEw5lP2UcIkXGrnUvG5iaro4VwbQM91Wq88vmY9Q/640?wx_fmt=png "")  
  
  
综上分析可知，漏洞出现的原因是POST 的URI中?service=  
后面的内容可由输入控制，全程没有对该处输入进行检查，直接sprintf后由system函数执行。  
  
#### 5.2 漏洞复现  
  
  
此漏洞涉及到的是UPnP的SOAP（简单对象访问协议）相关内容，SOAP主要是用于保证UPnP设备具有互操作能力。控制点可以调用UPnP设备上的服务，并接收返回结果。根据UPnP官方文档，要调用UPnP设备上的服务，控制点必须以POST方法发送以下格式的请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S18BKKlS9pYd68AQzg72t1JXRkd615056Yibhl42V02dOXCiaeib0BMToOA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1KbvnxX9S7qEo69E5aSrsxDxKDpwUV6yAHqsep2kCrkpTJj8mK6icWGw/640?wx_fmt=png "")  
  
  
由上面的分析可知要构造的POST请求头如下：  
  
  
```
```  
  
  
  
Poc脚本执行后，成功取得shell：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1NHv4ib0T8N48AqhdHjBJh9pdC54d8W38yMfyBq11aoIraVgUDDQ8Fhw/640?wx_fmt=png "")  
####   
#### 5.3 Poc  
  
  
```
```  
  
###   
###   
```
```  
####   
#### 6.1 漏洞分析  
  
  
根据漏洞披露的信息可知和ssdpcgi_main函数以及cgibin文件有关，将cgibin文件拿到IDA中分析并直接搜索ssdpcgi_main函数，调用该函数的代码为：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1gJWFnnq9I4lEafzaRqAzvxnmZCKmD5zygPSB2xhLPD4GFzZMIATOicw/640?wx_fmt=png "")  
  
  
根据前面分析的漏洞可知，这次漏洞请求URL中的文件是ssdpcgi。ssdpcgi_main函数中漏洞点关键代码如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1gC5tmCv50rjkX7SqOiaTOWWzI5NutBbIfne4iahoj2FHNic4icjQewOfYQ/640?wx_fmt=png "")  
  
  
根据上图代码可知要实现命令注入需要的环境变量如下：  
  
◆HTTP_ST：uuid:  
  
◆REMOTE_ADDR  
  
◆REMOTE_PORT  
  
◆SERVER_ID  
  
  
这些数据被传入lxmldbc_system  
函数，在该函数中直接拼接执行，没有任何检查。这几个环境变量中只有HTTP_ST是需要请求头设定的，即HTTP_ST是可控制的输入，因此HTTP_ST的值即为漏洞点。  
  
#### 6.2 漏洞复现  
  
  
此漏洞涉及到的是UPnP的SSDP（简单服务发现协议）相关内容，该协议主要是用于发现网络中的UPnP设备。控制点（用户操作的HTTP客户端）可以通过使用简单服务发现协议，根据自己的需要在网络中查询能够提供特定服务的设备。相应的设备（也就是本路由器）向控制点发出回应，声明自己的存在及能提供的服务。该协议在HTTP之下使用的是UDP。控制点需要用以下格式发送请求：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1tJ5ibeUuhoPSVAG0kQESRqUQL7LTDwiaGj25bCJPcInBicWD6m9Z3UV4g/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1JPydMfUicUo6WdTWTmA5RLHUjnYkyHZDkdeoujLqnR4EYD6wsBgsibnA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1GPl9gDfwvfJlTZjIMbafcOUODtW4DlA5WFoawyQ8UNDsCdycVFbTmg/640?wx_fmt=png "")  
  
  
综上分析，结合UPnP文档和/var/run/httpd.conf文件内容 可知要构造的请求头如下：  
  
  
```
```  
  
  
  
Poc脚本执行后，成功取得shell：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1x2Cb51yAZBvgy4VzJNkFMNTAVf45ATRdNiaLkFN8oNR2BlPiciaflrB7A/640?wx_fmt=png "")  
####   
#### 6.3 Poc  
  
  
```
```  
  
###   
###   
```
```  
####   
#### 7.1 漏洞分析  
  
  
根据漏洞披露的信息可知和hnap_main函数以及cgibin文件有关，将cgibin文件拿到IDA中分析并直接搜索hnap_main函数，调用该函数的代码为：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S19rYLtQwOqIM916jQeYBoug2jf27mWshRNJLsIPA0Xolic95GVonsIsw/640?wx_fmt=png "")  
  
  
hnap_main函数中关键代码如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S19lEKicgvTdNcpsNwLeToiaLSXv0tXrIHHhc044Cmw5ZgOAw8813yI43A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1DaPFB1wFM7RpwIAhJYFXIafp2gNv4icicfz0RAOYsicT9jo3HU0k8GTYQ/640?wx_fmt=png "")  
  
  
代码中没有对HTTP_SOAPACTION  
的值进行检查，直接将其内容中“/”后的内容拼接到buffer中执行。要想HTTP_SOAPACTION  
的值被作为注入点执行，请求方式不能为POST，可设定为GET，URL为/HNAP1/  
。  
  
#### 7.2 漏洞复现  
  
  
Poc脚本执行后，成功取得shell：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1LxFfEYqanOgTNDAset4j1ce07Mtx9LRwicBic0dsTVQibMwRVQqzQSibsg/640?wx_fmt=png "")  
####   
#### 7.3 Poc  
  
  
```
```  
  
###   
###   
```
```  
  
  
根据漏洞披露的信息，此漏洞和/htdocs/upnpinc/gena.php  
文件有关。查看该文件内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S1sgF8aGsckCfVb4xVGJC3uBzAWxJFJII9Efh80EUibNJtRmfxFLxxxKA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EibNpB8ibUsBVL66eEX8w6S12miaha8Klp3IAmvElSBykHtPJiaKXJia26oxytJR4dqD0w6icuNOBvtUdQ/640?wx_fmt=png "")  
  
  
通过查找该文件相关函数调用关系发现此漏洞和CVE-2023-34800所提及的是同一个漏洞。那么此漏洞的复现过程及Poc见CVE-2023-34800。  
  
  
```
```  
  
  
D-Link Go-RT-AC750相关的命令注入漏洞复现就告一段落了，起初看到一个设备有这么多命令注入漏洞，就很好奇会不会是同一个原因造成的，经过逐一复现后发现也能算是同一个原因，使用UPnP服务不检测输入的原因。这个固件把UPnP的GENA、SOAP、SSDP等位置的漏洞都触发了一遍，是一个很好的学习UPnP漏洞的样本。  
  
  
```
```  
  
  
◆  
CGI编程完全手册-阿里云开发者社区 (aliyun.com)  
  
（https://developer.aliyun.com/article/244192）  
  
  
◆  
Universal Plug and Play Device Architecture (upnp.org)  
  
（http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf）  
  
  
◆  
UPnP协议CallStranger漏洞影响数百万设备 - FreeBuf网络安全行业门户  
  
（https://www.freebuf.com/vuls/242386.html）  
  
  
◆[  
原创] cgibin中与upnp协议有关的一些漏洞分析与复现-智能设备-看雪-安全社区|安全招聘|kanxue.com  
  
（https://bbs.kanxue.com/thread-272634.htm）  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EPhvB3AhcBlFe7UWETytoBQqIhKIlCYR423QQIqzVwAU7baCgOtkxGy95p9UDU3AO8cRjIlWgGMQ/640?wx_fmt=png "")  
  
  
**看雪ID：伯爵的信仰**  
  
https://bbs.kanxue.com/user-home-882513.htm  
  
*本文为看雪论坛精华文章，由 伯爵的信仰 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458499288&idx=1&sn=b2b9cd6ff7388a8658d254e13c72f9ad&chksm=b18e885286f9014436a590f2531fda167be67e1e227ea395812968e828932bd44eade34b0dbf&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1、[在 Windows下搭建LLVM 使用环境](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500602&idx=1&sn=4bcc2af3c62e79403737ce6eb197effc&chksm=b18e8d7086f9046631a74245c89d5029c542976f21a98982b34dd59c0bda4624d49d1d0d246b&scene=21#wechat_redirect)  
  
  
2、[深入学习smali语法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500599&idx=1&sn=8afbdf12634cbf147b7ca67986002161&chksm=b18e8d7d86f9046b55ff3f6868bd6e1133092b7b4ec7a0d5e115e1ad0a4bd0cb5004a6bb06d1&scene=21#wechat_redirect)  
  
  
3、[安卓加固脱壳分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500598&idx=1&sn=d783cb03dc6a3c1a9f9465c5053bbbee&chksm=b18e8d7c86f9046a67659f598242acb74c822aaf04529433c5ec2ccff14adeafa4f45abc2b33&scene=21#wechat_redirect)  
  
  
4、[Flutter 逆向初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500574&idx=1&sn=06344a7d18a72530077fbc8f93a40d8f&chksm=b18e8d5486f904424874d7308e840523ebfb2db20811d99e4b0249d42fa8e38c4e80c3f622c6&scene=21#wechat_redirect)  
  
  
5、[一个简单实践理解栈空间转移](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500315&idx=1&sn=19b12ab150dd49325f93ae9d73aef0c4&chksm=b18e8c5186f90547f3b615b160d803a320c103d9d892c7253253db41124ac6993d83d13c5789&scene=21#wechat_redirect)  
  
  
6、[记一次某盾手游加固的脱壳与修复](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500165&idx=1&sn=b16710232d3c2799c4177710f0ea6d41&chksm=b18e8ccf86f905d9a0b6c2c40997e9b859241a4d7f798c4aeab21352b0a72b6135afce349262&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球在看**  
  
