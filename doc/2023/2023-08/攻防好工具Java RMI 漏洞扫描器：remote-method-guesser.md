#  攻防好工具Java RMI 漏洞扫描器：remote-method-guesser   
枇杷五星加强版  黑伞安全   2023-08-29 17:06  
  
https://github.com/qtc-de/remote-method-guesser  
### Remote Method Guesser  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8v6VYNSfMwqjuO96DJXOtMIzkYVEYhWdJlZZDYVEfQ72iaA7mRTNxoxtp8Nqe4eNGWHSjheenfPMm/640?wx_fmt=svg "")  
   
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8v6VYNSfMwqjjakE3NZR2zAWibPrjVrFiaFfMq5oVgibvaTWUORzQpScjk7WmFLJZnmb2nbqPKty8Ib/640?wx_fmt=svg "")  
   
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8v6VYNSfMwqjJbs1NtVa5S0UFb3LagEWxbTSPAv19AsoRJBSiaKmsnYOibVEpnUbcuWkLiacTopOsQO/640?wx_fmt=svg "")  
   
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8v6VYNSfMwqj6NkDNlFVNOqFkFSicjwB9yKvrrKom6zGNomE1UAb3XeULNTQrsbYyRX1k6Cmux44T/640?wx_fmt=svg "")  
   
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8v6VYNSfMwqjF2Z9yD2Weyb8PaVRYYPoibjyxCmIkaiaej28Y83Yv0go3cyBJxfCsFz6ianwMYYRJOt/640?wx_fmt=svg "")  
   
![](https://mmbiz.qpic.cn/mmbiz_svg/thfLhcllFYrkZ7ibqSSRP8v6VYNSfMwqjt4qKicxZxjvjicic7ia4KyscBr9Ixm4XicTKPEvEx4fOEBvxDgC0RqFHiaqPibib8ibY8iaNnu/640?wx_fmt=svg "")  
  
  
remote-method-guesser (rmg) is a Java RMI vulnerability scanner and can be used to identify and verify common security vulnerabilities on Java RMI endpoints.  
  
Remote-method-guesser  
 ( rmg  
 ) 是一个Java RMI  
漏洞扫描器，可用于识别和验证Java RMI  
端点上的常见安全漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpfFxrDnhcUsa2G8luycttyGR6DKpZJPiamSJVHmr7YWTfQh0CkCCsBicB9uS8eSbrE4RNof3f40r6A/640?wx_fmt=png "")  
  
  
RMG已在  
美国黑帽2021  
的 Arsenal  
会议 上  
展示  
。  
会议记录和相应的幻灯片是公开的，可以通过以下链接找到：  
- 幻灯片：https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal  
  
- 录音：https: //youtu.be/t_aw1mDNhzI  
  
Remote -method-guesser  
存储库包含两个示例服务器，可用于练习Java RMI  
枚举和攻击。  
rmg -example-server  
公开了可以使用remote-method-guesser  
枚举和利用的常规RMI  
服务。  
rmg   
-ssrf-server  
公开了一个  
易受SSRF攻击的HTTP  
服务，并运行  
仅在本地主机上侦听的RMI服务。  
这可以用来练习远程方法猜测器  
和  
选项。  
这两个服务器都可以作为GitHub 容器Registry  
中的容器使用：  
  
  
  
  
  
 --ssrf  
--ssrf-response  
  
- SSRF 服务器 GitHub 包   
  
https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server  
- 示例服务器 GitHub 包  
  
https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-example-server  
### Table of Contents  
- 安装  
  
- 支持的功能  
  
- bind, rebind and unbind  
  
- call  
  
- codebase  
  
- enum  
  
- guess  
  
- known  
  
- listen  
  
- objid  
  
- roguejmx  
  
- scan  
  
- serial  
  
- More Features  
  
- Docker Image  
  
- Acknowledgements  
  
### 安装  
  
rmg  
是一个Maven  
项目，安装应该很简单。安装maven  
后  
 ，只需执行以下命令即可创建可执行.jar  
文件：  
```
```  
  
  
您还可以使用为每个版本  
创建的预构建包  
。开发分支的预构建包是自动创建的，可以在GitHub 操作页面  
上找到  
。  
  
rmg  
不包含ysoserial  
作为依赖项。  
要启用ysoserial  
支持，您需要指定文件的路径ysoserial.jar  
作为附加参数（例如），或者  
在构建项目之前更改  
rmg 配置文件--yso /opt/ysoserial.jar  
中的默认路径。  
  
  
rmg  
还支持bash  
自动完成。  
要利用自动完成功能，您需要 安装completion-helpers  
项目。  
如果设置正确，只需将完成脚本  
复制到您的~/.bash_completion.d  
文件夹即可启用自动完成。  
```
```  
  
### 支持的操作  
  
下面介绍了每个可用操作的简短示例。  
有关更详细的描述，您应该阅读包含有关rmg  
和Java RMI  
的更详细信息的文档文件夹  
 。  
所有提供的示例均基于  
rmg-example-server  
 和  
rmg-ssrf-server  
。  
它们都包含在该存储库的  
docker  
文件夹中，可用于练习Java RMI  
枚举。  
您可以自己构建相应的容器，也可以直接从GitHub 容器reg  
加载它们。  
```
```  
#### 绑定、重新绑定和解除绑定  
  
通过使用bind  
,rebind  
或unbind  
操作，可以修改RMI Registry  
中的可用绑定名称  
。  
这对于验证特别有用  
，它可以绕过本地主机限制并允许远程用户执行绑定操作。  
使用remote-method-guesser  
或  
action时  
，默认  
绑定RemoteObject ，这是jmx  
服务器  
使用的RemoteObject 。此外，您还需要指定RemoteObject  
所在的相应TCP 端点  
的地址   
CVE-2019-2684  
bind  
rebind  
  
javax.management.remote.rmi.RMIServerImpl_Stub   
  
  
  
  
可以找到（当客户端尝试使用您的绑定对象时应连接到的地址）。  
```
```  
  
  
通过使用remote-method-guesser的插件系统  
，还可以将自定义对象绑定到RMI Registry  
。  
要了解有关插件系统  
的更多信息，请参阅文档文件夹  
。  
#### 称呼  
  
使用remote-method-guesser的 call  
action，你可以调用远程方法，而无需编写任何Java代码  
。  
考虑该方法String execute(String cmd)  
存在于远程服务器上。  
该方法听起来很有前途，您可能希望使用常规Java RMI 调用  
来调用它。  
这可以通过使用以下命令来完成：  
```
```  
  
  
请注意，默认情况下调用远程方法不会创建任何输出。  
要处理操作生成的输出call  
，您需要使用Remote-method-guesser 的  
插件系统并注册一个ResponseHandler  
.   
该存储库的插件文件夹  
包含  
适合大多数情况的GenericPrint插件。  
要了解有关remote-method-guesser  
插件系统的更多信息，请参阅 详细文档文件夹  
。  
```
```  
  
  
在操作期间call  
，参数字符串将被计算为  
以下形式的Java 表达式  
new Object[]{ <ARG> }  
：。  
因此，您需要确保您的参数字符串符合该模式。  
例如，用作"id"  
参数会导致错误，因为参数被传递给id  
remote -method-guesser  
，并且生成的表达式new Object[]{ id }  
不是有效的Java表达式  
。  
相反，您需要使用'"id"'  
as 这导致new Object[]{ "id" }  
，这是有效的。  
  
此外，原始类型需要在其相应的对象表示中指定（例如，new Integer(5)  
而不是5  
）。否则它们不能在由Java 表达式Object[]  
创建的数组  
中使用  
。  
在RMI 调用  
期间，相应的参数将按预期使用，并且符合您指定的方法签名。  
对于更复杂的用例，您还可以使用 remote-method-guessers  
插件系统  
定义自定义  
。  
  
ArgumentProvider  
  
  
#### codebase  
  
Java RMI支持称为  
codebase的  
功能  
，其中客户端和服务器可以  
在RMI 调用  
期间指定可用于动态加载未知类的URL 。  
如果RMI 服务器  
接受客户端指定的codebase  
，则当客户端在RMI 通信  
期间提供恶意Java  
类时，可能会导致 远程执行代码  
。  
  
  
  
  
  
  
RMI 服务器  
上的codebase配置  
对于不同的组件可能有所不同：Activator  
、DGC  
、Registry  
和Application Level  
。 Remote-method-guesser  
允许您使用--signature <method>  
（应用程序级别）、 --component act  
（激活器）、--component dgc  
（分布式垃圾收集器）或--component reg  
（RMI Registry）以及操作来 单独测试每个组件codebase  
。  
  
应用级别  
：  
```
```  
  
  
RMI Registry  
：  
```
```  
  
  
分布式垃圾收集器  
：  
```
```  
  
  
活化剂  
：  
```
```  
  
#### 枚举  
  
该enum  
操作对指定的Java RMI  
端点执行多项检查并打印相应的结果。  
有关该操作生成的输出的更详细说明enum  
，您可以阅读相应的文档页面  
。  
```
```  
  
#### 猜测  
  
使用该guess  
操作时，remote-method-guesser  
尝试通过将方法哈希发送到远程服务器来识别现有的远程方法。  
此操作需要一个包含相应方法定义的单词列表。 Remote-method-guesser  
.jar  
提供了一些在构建阶段  
包含在文件中的默认单词列表。  
您可以通过修改rmg 配置文件  
或使用--wordlist-file  
 或--wordlist-folder  
选项来覆盖单词列表位置。  
在猜测过程中会跳过零参数的方法，因为它们会导致服务器端真正的方法调用。  
您可以使用开关启用对零参数方法的猜测--zero-arg  
。  
```
```  
  
#### enum  
  
执行enum  
操作时，remote-method-guesser  
将RMI Registry  
上的可用绑定名称标记  
为known  
或unknown  
。  
此决定取决于相应绑定名称实现的类以及相应类是否包含在远程方法猜测器  
存储库中包含的  
已知端点列表  
中。  
当绑定名称  
标记为已知  
时，您可以使用  
  
  
  
  
  
  
  
known  
对相应的类进行操作。  
这样做会返回相应类的信息，例如可用的远程方法、一般描述和可能的漏洞：  
```
```  
  
  
已知类的列表、它们的描述以及已知漏洞的列表还远未完成。  
它有望在未来增长，并由其他用户的输入驱动。  
如果您遇到实现当前缺少的类的RMI 端点  
 ，并且您有足够的信息（描述和可用方法），请随意创建问题或拉取请求。  
#### 听  
  
有时需要提供恶意JRMPListener  
，它为传入的RMI  
连接提供反序列化有效负载。  
没有必要从头开始编写这样的侦听器，因为 ysoserial 项目  
已经提供了它。 Remote-method-guesser提供了  
ysoserial  
实现的包装器，它允许您  
 使用常用的rmg  
语法生成JRMPListener  
：  
```
```  
  
#### 对象  
  
该objid  
操作可用于显示有关 的更详细信息ObjID  
。  
每个RemoteObject在由  
RMI 运行ObjID  
时导出时  
都会被分配一个  
。与RemoteObject  
通信需要  
了解该值，这也是您通常需要RMI Registry  
的原因  
。  
RMI Registry  
包含  
 每个绑定名称  
的，并且远程方法猜测器  
在操作期间显示它们  
。  
ObjID  
  
  
  
ObjID  
  
  
enum  
```
```  
  
  
ObjID  
值由不同的组件组成。objid  
当对相应的操作  
使用时，这些组件将以人类可读的形式显示ObjID  
：  
```
```  
  
  
大多数显示的信息都没有那么有用，但时间  
值可能很有趣。  
该值包含创建RemoteObject  
的时间。因此，它允许您确定RMI  
服务器的正常运行时间等信息   
。  
#### 扫描  
  
有时，您确定了通常  
随其一起提供Java RMI组件的服务（   
JBoss  
、Solr  
、Tomcat  
等），但您不希望在相应的主机上执行完整的端口扫描。  
在这些情况下，该scan  
操作可能很有用。它仅对常见RMI  
端口执行快速端口扫描  
，并尝试识别它们上的RMI  
服务：  
```
```  
  
  
默认情况下，扫描操作使用预配置的常见RMI 端口  
列表  
。  
要自定义要扫描的端口列表，您可以使用该--ports  
选项。  
此选项接受端口规范的纯数字和数字范围。  
短划线字符 ( -  
) 可用于引用默认端口列表。  
```
```  
  
  
请注意，该scan  
操作是以简单且不可靠的方式实现的。如果可能，您应该始终使用nmap  
等工具执行专用端口扫描  
。  
然而，该scan  
操作可以让您快速了解如何查找RMI 端口  
。  
#### 流氓JMX  
  
这些roguejmx  
操作在您的系统上创建一个JMX 侦听器  
，用于捕获传入连接的凭据。  
创建侦听器后，remote-method-guesser  
会打印  
与其交互所需的ObjID值。  
```
```  
  
  
使用bind  
和rebind  
操作，您可以将此侦听器注入RMI 注册表  
并等待其他用户连接到您的服务器：  
```
```  
  
  
传入连接由侦听器记录：  
```
```  
  
  
  
默认情况下，remote-method-guesser  
使用ObjID  
值进行绑定  
操作和 rouge JMX  
服务器。  
因此，无需如上所示手动  
指定ObjID 。  
您可以通过命令行参数或在Remote-method-guesser 的  
配置文件中  
更改默认 ObjID值。[6633018:17cb5d1bb57:-7ff8, -8114172517417646722]  
  
  
  
  
  
  
默认情况下，恶意JMX  
服务器会为每个传入连接返回访问异常（无效凭据），但您也可以将传入连接转发到不同的JMX  
实例。  
这使得可以从传入的客户端连接获取凭据，而无需中断任何服务。  
要转发连接，您必须指定相应的目标作为附加参数。  
可以通过两种不同的方式指定目标：  
1. RMI Registry的 IP 地址和端口以及相应JMX 实例  
的绑定名称：  
  
```
```  
  
1. JMX  
服务本身的 IP 地址和端口  
及其ObjID  
值：  
  
```
```  
  
#### 连续剧  
  
Java RMI  
在客户端服务器通信中  
使用Java 序列化对象。  
这使得它可能容易受到反序列化攻击  
。  
这些攻击可以针对不同的RMI 组件  
：  
- 众所周知的RMI 组件  
（RMI 内部结构  
）  
  
- RMI Registry  
  
- 数字GC  
  
- 活化剂  
  
- 用户定义的RemoteObjects  
（应用程序级别  
）  
  
##### 众所周知的 RMI 组件  
  
尽管现代RMI 服务器  
在这些众所周知的 RMI 组件  
( JEP290  
 ) 上应用反序列化过滤器  
，但较旧的服务器可能仍然容易受到反序列化攻击  
。Remote-method-guesser  
允许使用  
操作来验证这一点，该操作可以对Activator  
、分布式垃圾收集器  
( DGC  
 ) 或RMI Registry  
执行反序列化攻击。  
  
  
  
serial  
  
  
  
  
```
```  
  
  
对于RMI Registry  
，  
可以使用  
JRMPClient  
 或  
An Trinh绕过小工具绕过反序列化过滤器  
。  
这些小工具创建  
 不再应用反序列化过滤器的出站 RMI 通道  
。  
在此通道上，可以照常应用反序列化攻击，但这两种绕过方法都在最新版本的Java RMI  
中进行了修补。  
  
  
  
  
  
  
```
```  
  
  
在其enum  
操作期间，remote-method-guesser  
会通知您RMI 端点  
（旧版RMI 组件  
）上是否存在Activator  
。激活系统  
的默认实现  
不会为激活器 RemoteObject  
实现任何反序列化过滤器。  
因此，即使在最新的Java 版本上，对Activator  
端点的反序列化攻击也应该始终有效  
。  
  
  
  
  
  
```
```  
  
##### 应用层  
  
尽管现代Java RMI  
实现默认使用反序列化过滤器保护众所周知的 RMI 组件，但自定义   
RemoteObjects （  
实际的  
RMI  
应用程序  
）通常不受保护。  
因此，不仅在其参数中使用基本类型的远程方法还可用于反序列化攻击  
。  
Hans-Martin Münch  
的  
这篇  
博文  
 更详细地解释了这个问题。Remote-method-guesser  
可用于轻松验证此类漏洞。  
作为示例，我们可以使用远程方法猜测器  
的方法  
  
  
  
  
  
  
  
  
String login(java.util.HashMap dummy1)  
  
执行反序列化攻击的示例服务器：  
```
```  
  
### 更多功能  
  
Remote-method-guesser包含许多在此  
README.md  
文件中未解释的功能  
。  
下面列出了其中一些：  
- 几乎所有操作都可以与为相应操作--ssrf  
创建SSRF  
有效负载的选项一起使用。  
  
- 如果您获得了二进制RMI 服务器  
输出（例如，在SSRF  
攻击之后），您可以 使用该选项  
将其输入到Remote-method-guesser  
--ssrf-response  
中。  
这会解析通过指定操作获得的服务器输出。  
  
- Remote-method-guesser可以通过使用它的  
插件系统  
来扩展  
。  
可以使用  
四个接口（IPayloadProvider  
、IResponseHandler  
和 ）将Remote-method-guesserIArgumentProvider  
用于更复杂的使用  
场景。ISocketFactoryProvider  
  
  
- 在guess  
操作过程中，您可以使用该--create-samples  
选项生成  
可用于调用成功猜测的方法的Java代码。  
  
有关这些功能的更多信息可以在文档文件夹  
中找到  
。  
### Docker 镜像  
  
从版本开始v4.4.0  
，remote-method-guesser  
也可以作为 docker 镜像提供，并且可以从 GitHub 容器Registry  
中提取。  
每个版本都有普通  
版和精简  
版。两者都提供了Remote-method-guesser  
的完整工作版本   
，但只有普通  
版本附带ysoserial  
 ，导致图像尺寸更大：  
- docker pull ghcr.io/qtc-de/remote-method-guesser/rmg:4.4.0  
-121MB  
  
- docker pull ghcr.io/qtc-de/remote-method-guesser/rmg:4.4.0-slim  
-61.9MB  
  
您还可以通过运行以下命令自行构建容器：  
```
```  
  
### 致谢  
  
Remote-method-guesser  
深受Hans-Martin Münch  
 和Jake Miller  
的博客文章的影响。  
此外，rmiscout 单词列表  
显然是从rmiscout  
 项目复制的（正如您已经可以通过不同的许可协议看出的那样）。  
感谢Jake  
，提供了  
从不同GitHub存储库收集的远程方法  
的精彩单词列表。  
  
版权所有 2023，Tobias Neitzel 和远程方法猜测器贡献者。  
  
  
