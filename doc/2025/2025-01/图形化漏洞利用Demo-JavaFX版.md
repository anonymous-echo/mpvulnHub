#  图形化漏洞利用Demo-JavaFX版   
原创 Iuochen  网络安全杂记   2025-01-13 04:46  
  
## 0x00 引言  
  
     这是一个专注于构建图形化漏洞利用工具的项目。项目目前已经搭建好了基本的框架结构，就像一座大厦已经建好了骨架，现在只需要往里面填充漏洞利用代码（exp）就可以了。这个项目的目标是助力安全人员迅速打造一个具备图形化界面并且能在多个平台使用的漏洞利用工具。  
  
在众多的漏洞利用工具里，虽然命令行工具也有其优秀之处，但是图形化的工具具有独特的优势。它更加方便、直观，能够让使用者更轻松地操作和理解。  
  
使用这个项目的时候，你不需要精通Java语言，只要对Java的基本语法有所了解就行。我们可以参照项目中自带的EXP示例，按照示例的模式和要求进行操作，这样就能够快速开发出独属于自己的漏洞利用工具，进而构建起自己的漏洞利用库。  
  
  
源地址：  
https://github.com/yhy0/ExpDemo-JavaFX  
## 0x01 正文  
  
 |   项目结构  
```
├── ExpDemo-JavaFX.iml
├── logs          运行日志文件
│   ├── debug.log
│   └── error.log
├── pom.xml
└── src
    └── main
        ├── java
        │   └── fun
        │       └── fireline
        │           ├── AppStartUp.java    应用程序启动入口
        │           ├── controller    控制JavaFX图形化界面的各种显示、事件等，核心代码 
        │           │   ├── MainController.java  主界面的controller，负责切换界面和基本信息显示
        │           │   ├── OAController.java   OA漏洞利用切换界面的相关逻辑
        │           │   ├── OthersController.java  其他漏洞界面的相关逻辑
        │           │   ├── Struts2Controller.java  Struts2漏洞利用界面的相关逻辑
        │           │   └── oa      OA漏洞利用的相关逻辑
        │           │       └── OASeeyonController.java
        │           ├── core     核心代码文件夹
        │           │   ├── Constants.java   一些常量基本信息
        │           │   ├── ExploitInterface.java   exp 编写要实现的接口
        │           │   ├── Job.java    一种漏洞全部检查的类
        │           │   └── VulInfo.java
        │           ├── exp			各种 exp 实现类
        │           │   ├── apache
        │           │   │   └── struts2
        │           │   │       ├── S2_005.java
        │           │   │       ├── S2_009.java
        │           │   │       ├── S2_016.java
        │           │   │       ├── S2_019.java
        │           │   │       ├── S2_032.java
        │           │   │       ├── S2_045.java
        │           │   │       ├── S2_046.java
        │           │   │       └── S2_DevMode.java
        │           │   ├── cms
        │           │   │   └── nc
        │           │   │       └── CNVD_2021_30167.java
        │           │   ├── oracle
        │           │   │   └── CVE_2020_14882.java
        │           │   └── others
        │           │       └── CVE_2021_22986.java
        │           └── tools  工具文件夹
        │               ├── HttpTool.java  HTTP 请求封装
        │               ├── MyCERT.java    HTTPS 请求证书设置
        │               └── Tools.java     一些处理函数
        └── resources    资源文件夹
            ├── css      界面css样式表
            │   └── main.css
            ├── fxml    界面的设计文件
            │   ├── Main.fxml
            │   ├── OA.fxml
            │   ├── Others.fxml
            │   ├── Struts2.fxml
            │   ├── Weblogic.fxml
            │   └── oa
            │       ├── OA-E-office.fxml
            │       ├── OA-Kingdee.fxml
            │       ├── OA-Landray.fxml
            │       └── OA-Seeyon.fxml
            ├── img
            │   ├── sec.png
            │   └── weixin.jpg
            └── log4j.properties   日志相关设置
```  
  
|  编写EXP  
  
编写EXP时，要使用 implements  
实现ExploitInterface  
接口，实现接口中的几个方法  
  
ExpDemo-JavaFX工具新增漏洞编写教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gjZLjBKtmAtFGQ3C6SGKiacrFpJw80tkNiaku0iblujlI5pxXT35llRo4kVHr2Viaa8Pp2jyf7Dia0KkvGeFH8sPwLQ/640?wx_fmt=png&from=appmsg "")  
```
-   checkVUL     使用poc 检查是否漏洞
-   exeCMD            使用exp执行命令
-   uploadFile        使用命令执行 写webshell，上传文件
-   getWebPath        获取网站的web目录，供上传文件使用
-   isVul              是否存在漏洞，检查时会根据结构自动赋值，供后续调用
```  
  
EXP具体编写请参考 fun/fireline/exp  
 下的各种漏洞实现  
  
当编写完EXP后，  
转到 fun/fireline/controller  
 下对应的**xxController.java**  
文件，比如新编写了Struts2的相关漏洞，修改**Struts2Controller.java**  
的**STRUTS2**  
变量，新加入一个漏洞名称，这里对应的是图像化界面中可供选择的漏洞列表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gjZLjBKtmAtFGQ3C6SGKiacrFpJw80tkNw5MkVOib0zqniaK2EyDktJMSrLQxdOaJv4O8Amu2uE4tcwibaVxQj4sJA/640?wx_fmt=png&from=appmsg "")  
  
之后进入和 fun/fireline/tools/Tools.java  
 的**getExploit**  
方法中新增一个**else if**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gjZLjBKtmAtFGQ3C6SGKiacrFpJw80tkNKhnNiaLSIfUaGOHxDeFOQibvicVBBFEhEzuRNUWT6AqAvnuibPg6M6G7sA/640?wx_fmt=png&from=appmsg "")  
  
编写完后，可以直接执行fun/fireline/AppStartUp.java  
类, 查看是否正常运行。  
  
开发过程中每次修改完运行前，最好将生成的**target**  
目录删除再运行  
## 0x02 部署  
  
  
在项目开发和测试完成后，一旦所有的编写工作结束并且bug得到了修复，您可以在项目的根目录下执行以下命令：  
```
mvn package assembly:single
```  
  
这条命令将会生成一个可执行的JAR文件。为了运行这个项目，您可以使用target  
目录下生成的较大JAR文件。  
  
如果您在没有Java环境的机器上运行，可以使用以下命令来生成对应平台的可执行文件：  
```
mvn jfx:native
```  
  
例如，在Mac系统下执行此命令，将会在target/jfx/native  
目录下生成一个打包后的应用程序（在Windows系统下会生成.exe  
文件）。这个打包的应用程序包含了可执行文件和JRE运行环境，因此文件体积较大，通常超过200MB。  
  
如果您需要清除之前生成的文件，可以使用以下命令：  
```
mvn clean
```  
  
此外，您也可以通过双击ExpDemo-JavaFX-1.9/src/main/java/fun/fireline/AppStartUp.java  
来启动项目，这种方式适用于开发过程中的快速测试。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gjZLjBKtmAtFGQ3C6SGKiacrFpJw80tkNTOYSug2ic0QicQ9qF7Al3yyIGMo4AQicfBtWGBMkeXPm5ib2obBqN3XnNQ/640?wx_fmt=png&from=appmsg "")  
  
