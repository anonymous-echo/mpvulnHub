#  Log4Shell漏洞的长期影响   
 关键基础设施安全应急响应中心   2022-07-20 15:25  
  
Log4Shell漏洞(CVE-2021-44228)早在6个多月前就被披露了，虽然已经出现了很多防御方法。但该漏洞的影响至今都在。CISA最近发出警告，攻击者正在使用Log4Shell利用VMWare Horizon服务器来发起攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogs74ialrQ0zHYy9qazOElz1ZHmQuSDxIel4EMfqFicCzH7caZs2FEoKh3pZVzGlBRxZH2lEo75OGWKw/640?wx_fmt=jpeg "")  
  
到目前为止，对 Log4Shell 的大量利用都集中在众所周知的、广泛部署的应用程序上，例如 VMware Horizon、VMware vCenter 和 Unifi Network 应用程序。但这只是冰山一角。可能有数千个 Java 应用程序受到 Log4shell 不同程度的影响，并且有数千个新的漏洞利用路径有待发现。攻击者只需将注意力转移到企业运行的特定应用程序上，在一两天内，一个漏洞就可能被开发和武器化。  
  
研究人员将在下面详细介绍利用过程，并针对几个应用程序执行远程代码：VMware Site Recovery Manager、Elasticsearch 5 和 OpenNMS。这样做的目的是介绍Log4Shell 的广泛和长期影响以及开发漏洞利用的速度。最终，NodeZero 作为一种渗透测试工具的目标之一是揭示各种漏洞、漏洞配置和受损凭证的真正影响。研究人员相信这种影响最好通过实际利用的证据来证明。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5Yeu4jtQUDqMAoHBAPvovTDV1grsKmORFBSMhiauxm7GzyicEFVhRK5J3w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一般来说，Log4Shell 的利用过程包括两个步骤：  
  
识别 JNDI 查找注入点：这是未经身份验证的攻击者向应用程序发送的网络请求，该请求将导致应用程序使用易受攻击的 Apache log4j2 库记录消息，进而导致应用程序对攻击者托管的服务器进行JNDI查找。  
  
确定从攻击者托管的服务器提供的 Java 有效负载：这是由易受攻击的应用程序通过 JNDI 查找检索并反序列化以执行远程代码的有效负载。  
  
第一步，为了验证 JNDI 查找注入点，研究人员使用了 dnslog.cn 上的 DNSLog 服务来捕获来自易受攻击的应用程序的 DNS 回调。Burp Collaborator 或 Interactsh 服务器等其他工具也可用于此目的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogs74ialrQ0zHYy9qazOElz1ZrNOq6QYOJibMdDCAbcYzsbXVtVBVtUyWR7l0dG5LUaOFXicrDsG78FsA/640?wx_fmt=jpeg "")  
  
使用了以下工具利用：  
  
https://github.com/pimps/JNDI-Exploit-Kit  
  
https://github.com/veracode-research/rogue-jndi  
  
https://github.com/pimps/ysoserial-modified  
  
**利用 VMware Site Recovery Manager**  
  
VMware Site Recovery Manager 是“业界领先的灾难恢复 (DR) 管理解决方案，旨在最大限度地减少发生灾难时的停机时间。”它是 VMware Log4Shell 公告中受 Log4Shell 影响的众多 VMware 应用程序之一。研究人员在实验室中安装了 8.3.0 版本。该应用程序公开了两个端口，443 用于 SRM 应用程序，5480 用于管理 SRM 设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YNicIZxWHPgOOOF4bTqYxfH3ibyqxO0jvV5ViaFFqpibTf1iaywsHicj2Yqow/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**检测**  
  
为了快速获得成功，研究人员最初尝试将 JNDI 有效负载插入 SRM 应用程序登录表单的用户名字段，但未能获得 DNS 回调。因此，研究人员从 SRM 设备中提取 jar 文件并对其进行反编译，并开始探测未经身份验证的攻击者可以访问的 API 端点。在研究人员使用 error 参数确定 OAuth2LoginServlet 中的注入点后不久。servlet 可在 /dr/authentication/oauth2/oauth2login 端点访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YaddpsLgLTGXpNSIkPLuke1cWuzjyYZaTH26rD9gibO4AOLh3146KWEg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
研究人员通过发送这种形式的 HTTP GET 请求来验证注入点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YNs0NEfzGmYEeW5V4nIjBvGozTlibPc4rGG7pU3htibA4W2BND2Qg3HHQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
并得到了预期的 DNS 回调：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogs74ialrQ0zHYy9qazOElz1Znian5LHU0mbneL0T94AISkXibNZI7sxpNZxounqFBfCLLtsVzy88tqUQ/640?wx_fmt=jpeg "")  
  
**开发**  
  
与 Horizon 和 vCenter 一样，SRM 使用 Apache Tomcat 作为其应用服务器。无论 Java 运行时版本如何，易受 Log4Shell 攻击的基于 Tomcat 的应用程序很容易被用于远程执行代码。此处描述了通用技术，并由 JNDI-Exploit-Kit 工具自动执行。  
  
研究人员在攻击者服务器上启动了 JNDI-Exploit-Kit 以提供 bash 反向 shell 有效负载，以及一个netcat侦听器来捕捉端口9999上的反向shell：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5Y7Kf5Szu4bvTiboIibVC9RK46JIibmZ5U7JjAjgPjWicOVOoAYVDTk39OAQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后触发 HTTP 请求以触发对 JNDI-Exploit-Kit 服务器的回调：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YgDFGXCdsMCL7vrHel9C3jf4Ca3nC8cEWRVibWNxd0coDh8FHqVQtE6w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
并以tomcat用户的身份获得了一个shell：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5Y5lLhjw87ibcFF65avUH1wJ9sQibiamAaboM7BHicMAVe5TWSG77NEYiaSpQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
NodeZero 自动化了上述所有步骤，从而产生了以下证明，证明了针对易受攻击的 SRM 实例执行远程代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5Y6bDyIWRJhoKDB8dAB7kiaQPVJHOmfDpNgSgxxyaGb7L36wjc84lpzcg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**恶意影响**  
  
SRM 通常不在公网上。研究人员只发现其中约 20 个使用 Shodan 公开曝光。然而，研究人员确实偶尔会在内部渗透测试中看到它。研究人员建议根据 VMware 的建议将设备更新到最新版本或应用此处描述的解决方法。  
  
**利用 Elasticsearch 5**  
  
Elasticsearch 是一个流行的开源分布式搜索和分析引擎。Log4Shell 的 Elasticsearch 声明称，由于 Elasticsearch 使用 Java Security Manager锁定权限的方式，只有 Elasticsearch 5 容易受到远程代码执行的影响。在易受攻击的 Elasticsearch 版本 6 及更高版本中，应用程序将对攻击者控制的主机名执行 DNS 查找，但不会启动与攻击者控制的服务器的任何 TCP 连接。DNS 查找可用于泄露环境变量等系统信息，但无法远程执行代码。这可以通过 5.6 版与 6.0 版的 security.policy 文件中的差异看出。  
  
为了进行测试，研究人员从位于 docker.elastic.co/elasticsearch 的 Elasticsearch docker repo 中设置了各种版本的 Elasticsearch 5。  
  
**检测**  
  
研究人员发现了一些通过 Elasticsearch REST API 触发 JNDI 查找的方法，方法是创建类型等资源或触发弃用警告。然而，研究人员发现这些方法破坏性太大/噪音太大，或者它们不能普遍适用于所有版本的 Elasticsearch 5。  
  
仔细查看 Github 上的源代码和问题，研究人员发现了一个问题，表明在搜索请求中发送格式漏洞的 JSON 会触发内部服务器漏洞，然后记录下来。我们验证了这在Elasticsearch 5的所有版本以及超过7.6的版本上都可以使用。例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5Y7sszcvqMNzbUCqhJzBPE2Rsh1Yg1TEq18hT1zkSvwpG6CbIGQBtaxw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**触发此漏洞：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YhSzYRv78PNjW94VQdVWjWbmicTSlib8qtRlQAW3XMOwTwiauck5KnR4Rw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这会导致 DNS 回调：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogs74ialrQ0zHYy9qazOElz1ZH2tuvMk3JbTKwPNnS2iaLZxlBeyDdJJOQX208LicVQUA8vlgwpSon2sg/640?wx_fmt=jpeg "")  
  
**漏洞利用**  
  
Elasticsearch 在 Netty 框架上运行，因此针对 VMware Site Recovery Manager 的基于 Tomcat 的漏洞利用不适用于这里。研究人员决定找出一个最佳选择，这是针对运行 Java 运行时版本 < 8u191 的应用程序的远程类加载攻击。这种远程类加载攻击由 rogue-jndi 等工具自动执行。  
  
研究人员从 docker.elastic.co/elasticsearch 存储库中提取了一堆不同版本的 Elasticsearch 5，以了解它们捆绑的 Java 运行时版本。研究人员发现从 5.0.0 到 5.6.12 的所有版本都运行 Java 运行时版本 < 8u191，而从 5.6.13 到 5.6.16 的版本运行 Java 运行时 >= 8u191。虽然不是每个人都使用来自 docker.elastic.co/elasticsearch 的 Docker 镜像来运行 Elasticsearch，但研究人员推测，大多数在野外运行的 Elasticsearch 5 实例都可以利用远程类加载攻击来远程执行代码。  
  
研究人员发现，远程代码执行与任意代码执行是不同的。特别是，由于Elasticsearch使用了Security Manager，可以直接使用Runtime运行主机命令。无法执行exec或ProcessBuilder，并且对文件系统的访问受到限制。研究人员确实发现可以进行任意网络调用，从 /tmp 之类的几个目录读取/写入，以及像加密矿工一样在内存中运行东西。  
  
例如，为了向托管在 10.0.220.54 的内部服务器发送网络请求并将响应发送回攻击者的服务器的 9999 端口，研究人员修改了 rogue-jndi 中的 HTTPServer 类以使用以下有效负载：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YjPicdLS0MboBLUhL25ac1hjrKqqRD6eJY6N5VQibOhJauabCy0SPKia3g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
研究人员在 10.0.220.54 上设置了一个简单的测试内部服务器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YIibQcevcE4pgg1ZAWTCicvf1jRRVmaLgk0qmCMPmCHTj59DGsicHRME3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后在 9999 端口启动 rogue-jndi 和 netcat 监听器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YCNkJCNiau1SFnjgaZIc1qSVG2HbcFaGfpSnfDQDAib7gpK6INwGmPgzA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
并发送请求以触发 JNDI 查找：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5Y5o9cxGicuMWYrgrVTB1mFiapRfY5kGRUiaEWvpujQU30sjjeG4Hpr1CIw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
导致从内部服务器窃取数据：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YuibGqVsTP7XFsPH8ic1ic8bg9sMibHW2owy7tANZuDdt0CyZbjA8QaGcBQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
NodeZero自动执行上述所有步骤，从而产生了以下证明，展示了针对易受攻击的 Elasticsearch 实例执行远程代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YnLUHYTpGbBT2OAespOcQ3j2CTWoFyDJv2lwywm0ssOSP2EmrHnOT2A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
要利用运行 Java >= 8u191 的 Elasticsearch 5 版本，必须在 Elasticsearch 应用程序的类路径中的库中找到反序列化小工具。研究人员注意到 Elasticsearch 5 引入了 groovy-2.4.6-indy.jar 库，该库容易受到 CVE-2016-6814 的攻击，并且可以使用此处描述的技术进行利用。但是，研究人员被Security Manager阻止执行此小工具，因此没有进一步利用。  
  
**漏洞影响**  
  
使用 Shodan API，研究人员发现总共有 22914 台 Elasticsearch 服务器未经身份验证暴露在互联网上。其中，1275 台运行 Elasticsearch 5，其中 955 台服务器运行版本 <= 5.6.12，因此很可能运行 Java 运行时<8u191。基于此，研究人员估计公网上大约有 900-1000 台 Elasticsearch 5 服务器可利用上述技术进行远程代码执行。当然，在公网上拥有一个开放的 Elasticsearch 服务器已经很糟糕了。现在这些服务器也可以被滥用以转入内部网络。如果你运行的是易受攻击的 Elasticsearch 版本，研究人员建议你遵循 Elasticsearch 公告中的修复指南更新到最新版本。  
  
**利用 OpenNMS**  
  
OpenNMS 是一个开源的网络监控解决方案。研究人员使用此处的 docker-compose 模板安装了OpenNMS Horizon 26.2.2版本。  
  
**检测**  
  
为了快速获得成功，研究人员尝试将 JNDI 有效负载注入登录表单的用户名字段，并且成功了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YqPzM5zmHeCxTrFNJsneMFpRjjtC4Fc47Durw6j72UlSkNzGdJyicZiaQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
DNS回调：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogs74ialrQ0zHYy9qazOElz1Zfv5mPpnbiahSBLGmxfNlVPjyFHQhdjvM953sbBwmAus8h9ZickVJ1bPg/640?wx_fmt=jpeg "")  
  
使用cur：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YSQJHR9wCAfz3nkbAJxYbtuzIn34b6zNKY8r2xxd9xP4H8iaX8UhrgcA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
研究人员检查了日志，发现用户名正在被HybridOpenNMSUserAuthenticationProvider类记录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YEgrYuDOJgia9WzbrhIx4kFg7g5pz1RM7NM3bYBAs1NAfyU50BnbRPOA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在 Github 中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YLslVJOfP7zI9Huj59NfmnP1qjYMRcpEGbPRibyJ58fg8bHpGBoEaerg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**漏洞利用**  
  
研究人员使用的 OpenNMS 版本使用 Java 11.07 运行，使用 Jetty 作为应用服务器。这意味着研究人员针对 VMware Site Recovery Manager 使用的基于 Tomcat 的漏洞利用以及针对 Elasticsearch 5 使用的基于 JVM 的旧漏洞利用将无法正常工作。不过利用option 3: 在本地 OpenNMS 中提取的一个库中找到反序列化小工具。通过查看这些jar文件，研究人员找到了 commons-beanutils-1.9.4.jar，其中有一个众所周知的反序列化小工具可以使用 ysoserial。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YSvwccicIWQqtbYmiacxWMXe2mTTLC1m4QKKEQNaCXLLibyl5pum1MhibxQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
使用 ysoserial-modified 项目，研究人员创建了反向 shell 有效负载：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YS5TTo6YvooqafuRPQoqvBtE8WPddrou1sOEUJe84FibnTuGQnPZeaeA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后使用 JNDI-Exploit-Kit 为它提供服务，并在端口 9999 上启动了一个 netcat 侦听器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YMTwhP6CNCvq6LbvY49o5sCTZ50Tqibnk6bzVwQ5L6ic9j341dKdchkEQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后发送 curl 请求来触发漏洞利用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YicTfkRt6ibtDHAC8rBkV30Ebd83IX1ibptb70eDwhwgRibJc3FMfnfK7lg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
并得到了反向shell：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YzOlnwicohuSlUQm0vhj0aWlBcLe2xF3cZ06poGEVQiaTVDxVITwZn22A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
NodeZero 自动化了上述所有步骤，从而产生了以下证明，展示了针对易受攻击的 OpenNMS 实例执行远程代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibbVEMNMMMn72LxlPvlgG5YCQtmicxGuuBtkv2iaa2IG6DA9lennyVOEaLDXWfd9LJ63WAGNBhiaWl8w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
OpenNMS 通常不部署为面向在公网，从攻击者的角度来看，网络监控解决方案通常是有吸引力的攻击目标，因为它们通常存储用于访问环境中其他基础设施的凭据。研究人员建议根据 OpenNMS 公告更新到最新版本。  
  
**总结**  
  
攻击者是机会主义的。正如研究人员上面所展示的，Log4shell 是一个可以带来很多机会的漏洞。普通攻击者通常很难（如果不是不可能）发现导致已建立应用程序中未经身份验证的远程代码执行的漏洞。Log4Shell 可以在许多应用程序中实现这一点，而且攻击者可以轻松地将其作为武器。  
  
**参考及来源：**  
  
https://www.horizon3.ai/the-long-tail-of-log4shell-exploitation/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
