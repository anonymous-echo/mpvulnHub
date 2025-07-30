#  使用 Joern 查找用于利用 Java 中 Unsafe Reflection 漏洞的类   
 Ots安全   2025-04-19 08:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在一次渗透测试中，我们发现一个 Java 应用程序存在不安全反射漏洞 [1]。此应用程序允许我们实例化任意类，并将受控字符串作为参数传递给其构造函数。当我们意识到应用程序使用的依赖项时，我们提出了以下问题：我们如何自动化该过程以找到好的类？  
  
对于好的类，我们指的是符合条件（构造函数接收字符串）且具有安全隐患（可用于利用应用程序）的类。这篇博文将记录我们如何自动化此过程。  
  
**动机——CVE-2022-21724**  
  
我们在渗透测试中发现的漏洞是 PostgreSQL JDBC 驱动程序未检查类实例化 (CVE-2022-21724) [9]，其中可以实例化任意类，并通过 JDBC URL 获取可控制的字符串类型参数。有效载荷示例如下：  
  
```
jdbc:postgresql://127.0.0.1:5432/testdb?&socketFactory=CLASS&socketFactoryArg=ARGUMENT
```  
  
  
在查找相关记录时，我们发现了一些有趣的攻击[10][11]，这些攻击使用了 Spring 和其他库中的类，例如：  
- org.springframework.context.support.ClassPathXmlApplicationContext  
  
- org.springframework.context.support.FileSystemXmlApplicationContext  
  
- com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext  
  
- com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext  
  
- com.tangosol.coherence.mvel2.sh.ShellSession  
  
然而，这些类在我们的目标中都不可用。幸运的是，我们设法通过另一个漏洞访问了应用程序使用的库列表，并决定自动执行寻找适合我们攻击的类的过程。  
  
**静态分析**  
  
为了解决我们的问题，我们可以采用数据流静态分析，旨在识别从数据源到数据接收器的路径。在这个特定的场景中，我们定义数据源和接收器如下：  
- **source**  
 – 具有接受字符串作为参数的构造函数的类  
  
- **sink**  
 – 任何可用于利用应用程序的方法  
  
在理解了问题并定义了源和接收器之后，我们意识到需要一个工具来辅助进行这种分析。由于我们预计在只有编译后的 Java 代码可用的情况下需要分析依赖关系，因此我们寻找一种能够直接对 JAR 文件进行分析的工具。因此，我们选择使用 Joern [2]，它提供对 JAR 文件的支持，如 [3] 所示。  
  
**Joern**  
  
对于那些不熟悉 Joern 的人来说，它是一个代码分析平台，它使用一种称为代码属性图 (CPG) [4] 的结构。该平台使我们能够使用基于 Scala 的语言对代码执行查询，从而促进全面的代码分析。我们还可以使用 Joern 执行数据流分析，例如，看一下这个代码片段：  
  
```
import java.io.IOException; public class Example1 {    public Example1(String arg) throws IOException {         foo(arg);    }         public void foo(String arg) throws IOException {        Runtime.getRuntime().exec(arg);    } }
```  
  
  
我们可以使用以下 Joern 脚本来查找从源到接收器的路径：  
  
```
@main def main(code: String) = {    importCode(code)         // Get constructors that accepts stringas arg    val cons = cpg.method.isConstructor.signatureExact("void(java.lang.String)").l         // Get all calls to Runtime.exec    val name = "java.lang.Runtime.exec:java.lang.Process(java.lang.String)"    val calls = cpg.method.fullNameExact(name).callIn.l    // Source is the string passed to constructor    val source = cons.parameter.order(1).l         // Sink is the argument passed to Runtime.exec    val sink = calls.argument(1).l         // Print the path from sourceto sink     sink.reachableByFlows(source).p}
```  
  
  
运行脚本时，我们应该获得类似下表的结果：  
  
```
joern --script example1.sc --params code=Example1.java    nodeType | tracked | lineNumber| method | file =================================================================================== MethodParameterIn | <init>(this, String arg) | 4         | <init> | <unknown> Identifier | this.foo(arg) | 5         | <init> | <unknown> MethodParameterIn | foo(this, String arg) | 9         | foo | <unknown> Identifier | Runtime.getRuntime().exec(arg) | 10        | foo | <unknown>
```  
  
  
此示例说明了我们将要进行的分析类型，不同之处在于，我们不是针对源代码运行分析，而是针对编译后的代码执行分析。值得一提的是，在测试过程中，我们遇到了 Joern 的一个问题，当源数据在编译后的代码中分配给类的字段成员时，它无法捕获路径。我们已报告此问题 [5] [6]。  
  
**实验**  
  
为了验证识别合适类的过程，我们对几个著名的 Java 库进行了实验。为此，我们使用了以下方法：  
1. 列举有趣的接收器  
  
1. 下载库  
  
1. 静态分析方法  
  
1. 动态分析方法  
  
**列举有趣的接收器**  
  
为了选择用于数据流分析的接收器，我们列举了 Java 应用程序中一些最常见的对服务器端有直接影响的漏洞和攻击类型。列表如下：  
- 命令注入  
  
- 表达语言注入（EL、OGNL、MVEL、SpEL、JEXL）  
  
- 反序列化  
  
- 文件读/写  
  
- JDBC 驱动程序连接  
  
- SSRF  
  
- 命名实体接口  
  
- XML Bean  
  
- XXE  
  
- SQL 注入  
  
- 代码加载（System.loadLibrary、java.net.URLClassLoader 等）  
  
- 代码评估  
  
然后，对于每一个方法，我们选择一组在使用用户控制的数据调用时可能导致此类漏洞的方法。  
  
**下载库**  
  
我们创建了一个脚本 ( https://github.com/convisolabs/java_unsafe_reflection/blob/main/downloader/download.py ) 来下载最相关的 Java 库，以便运行我们的实验。简而言之，它会浏览流行/相关库的有序列表 [8]，并将每个 JAR 文件下载到本地目录。  
  
**静态分析方法**  
  
在枚举接收器并下载 JAR 后，我们开发了一个 Joern 脚本 ( https://github.com/convisolabs/java_unsafe_reflection/blob/main/joern_scripts/all_sinks_each_file.sc )，该脚本接受两个文件夹作为参数。一个文件夹表示 JAR 文件的位置，另一个文件夹用于存储结果。  
  
要执行脚本，请使用以下命令：  
  
```
joern --script all_sinks_each_file.sc --params inDir=jars,outDir=result
```  
  
  
该脚本将生成 JSON 格式的结果。输出文件将包含将源链接到接收器的路径。为了增强可读性，我们还创建了一个单独的脚本 ( https://github.com/convisolabs/java_unsafe_reflection/blob/main/utils/pretty_print_result.py )，以方便解释输出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacTyjG4iayw18c1XeGa2ObBRKeJC3gneV8LC1eTv2Q4VIaS3u7RrvW5JVzibqlpUgnW9IpxcicCf5fEw/640?wx_fmt=png&from=appmsg "")  
  
我们在开发和运行此分析时遇到的一些问题包括：  
  
我们在使用 Joern 时遇到了一个问题，当编译代码中的源数据被分配给类的字段成员时，它无法捕获路径 [5] [6]；  
  
如果没有足够的 RAM 内存，速度会很慢。此外，更大的文件需要更多的处理时间。我们跳过了一些较大的库进行下载；  
  
我们遇到了一些 Joern 无法很好处理的 Java 构造，这会导致其无法正确跟踪数据流，从而错过好的构造函数（假阴性）。  
  
尽管存在这些问题，分析仍然能够找到良好的结果。  
  
**动态分析方法**  
  
验证结果的一种方法是直接访问源代码（如果可用）或反编译 JAR 文件并尝试遵循已识别的路径。但是，这种方法仅适用于有限数量的结果或路径相对较小的情况，而我们的场景并非如此。相反，我们选择了动态验证。我们开发了一个代码，它接受一个类及其相应的参数，并尝试实例化它。  
  
然后，我们自动执行检索结果、提取构造函数并使用预先建立的参数列表实例化它们的过程。此列表包含经过精心挑选的值，用于验证各种场景，包括访问服务器、创建文件、执行系统命令等。我们还记录了所有执行，以便能够手动检查。该脚本可在https://github.com/convisolabs/java_unsafe_reflection/blob/main/utils/tester.py中查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rWGOWg48tacTyjG4iayw18c1XeGa2ObBRUiaOoBVPEoia6uzeiblYTIludANIf6tvyGiaic8u2aY0ewpHm8mcKIC1hLg/640?wx_fmt=gif&from=appmsg "")  
  
在 GIF 中，屏幕上部显示  
tester.py  
脚本正在运行http://tester.py/，下部显示生成的日志的实时检查（tail -f /tmp/tester.dd-mm-yyyy_HHhMMmSSs.log）。  
  
这种动态验证方法使我们能够更高效、更有效地验证研究结果。  
  
**发现**  
  
由于获得的结果数量太多，我们仅审查了其中的一小部分，以下只是我们发现的一些有趣的构造函数：  
  
**MySQL 客户端任意文件读取**  
  
软件包：mysql-connector-java-8.0.11.jar  
  
类：com.mysql.cj.jdbc.admin.MiniAdmin  
  
参数：jdbc:mysql://rogue_server  
  
**XXE、SSRF 和任意文件读取**  
  
软件包：mybatis-3.5.13.jar  
  
类：org.apache.ibatis.parsing.XPathParser  
  
Arg：XXE 窃取载荷  
  
**不安全的反序列化**  
  
软件包：jasperreports-6.20.5.jar  
  
类：net.sf.jasperreports.export.SimpleExporterInput  
  
Arg：序列化漏洞的文件路径  
  
**任意文件内容因错误而泄漏**  
  
软件包：dnsjava-3.5.2.jar  
  
类：org.xbill.DNS.tools.jnamed  
  
参数：/etc/passwd  
  
**SSRF**  
  
软件包：itextpdf-5.5.13.3.jar  
  
Classes：  
- com.itextpdf.text.pdf.codec.GifImage  
  
- com.itextpdf.text.pdf.RandomAccessFileOrArray  
  
参数：URL  
  
**SSRF**  
  
软件包：itext-4.2.1.jar  
  
Classes：  
- com.itextpdf.text.ImgWMF  
  
- com.lowagie.text.pdf.codec.GifImage  
  
参数：URL  
  
**可能存在 Webroot 路径泄漏错误**  
  
软件包：hutool-core-5.8.19.jar  
  
类：cn.hutool.core.io.file.FileReader  
  
Arg：一些不存在的文件名（例如xxx）  
  
**命令注入**  
  
软件包：jline-2.14.6.jar  
  
Classes：  
- jline.internal.TerminalLineSettings  
  
- jline.Unix终端  
  
参数：$(命令)  
  
**结论**  
  
在这篇博文中，我们介绍了一种简单的方法，可以自动发现在攻击 Java 应用程序中不安全的反射时要使用的有趣类。我们展示了如何使用 Joern 执行适合我们需求的自定义数据流分析。  
  
在 2023 年 Blackhat Asia 大会上，徐元振和 Peter Mularien 发表了一项有趣的研究，题为“Java 应用程序中的新攻击接口”[7]，其中展示了通过 JDBC URL 寻找良好类来利用类似漏洞的过程的其他示例。  
  
后续工作可能是在 Java 代码本身中运行我们的分析，以发现不依赖于外部库的有趣构造函数。另一个可能是利用脚本来查找 Java 应用程序中的安全漏洞，只需重新定义源以表示用户控制的数据（例如 HTTP 请求参数）。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
