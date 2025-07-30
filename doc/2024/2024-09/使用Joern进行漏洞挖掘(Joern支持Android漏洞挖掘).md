#  使用Joern进行漏洞挖掘(Joern支持Android漏洞挖掘)   
 哆啦安全   2024-09-17 09:31  
  
使用 Joern 进行漏洞挖掘  
  
曾几何时，在 [代码安全审计之道](https://mp.weixin.qq.com/s?__biz=MzA3MzU1MDQwOA==&mid=2247484037&idx=2&sn=c20f18255f488deabd3bfab07da5dbd5&scene=21#wechat_redirect)  
 一文中介绍了一些形而上学的代码审计方法论，在该文章提及未来会继续介绍一些具体的漏洞挖掘工具和技巧，即代码安全审计之术。正所谓白驹过隙，光阴荏苒，不知不觉两年多过去了，由于怠惰一直没有动笔。不过我也一直没有忘记这茬，正好最近放假就给自己补上。  
  
本文是使用开源的 Joern 来进行漏洞挖掘的介绍。  
# Joern 101  
  
Joern  
[1] 是一个开源的代码分析平台，可以通过多种不同的前端将源代码转换为代码属性图(Code Property Graph)，简称 CPG，然后通过 Joern 内置的查询语法对 CPG 进行查询和分析。如果读者对   
CodeQL  
[2] 比较了解的话，可以将 Joern 理解成开源版的 CodeQL。  
  
Joern 通过不同的前端引擎支持不同的代码，比如使用 CDT 支持 C/C++ 代码的 fuzzing parsing，使用 Ghidra 支持二进制文件的解析，使用 Soot 支持 Java 字节码的解析等等。不同前端的成熟度有所不同，如下表所示：  
  
<table><thead style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;background: rgba(0, 0, 0, 0.05);font-weight: bold;color: rgb(63, 63, 63);"><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;padding: 0.25em 0.5em;word-break: keep-all;">Name</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;padding: 0.25em 0.5em;word-break: keep-all;">Built with</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;padding: 0.25em 0.5em;word-break: keep-all;">Maturity</td></tr></thead><tbody style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">C/C++</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Eclipse CDT</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Very High</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Java</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">JavaParser</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Very High</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">JavaScript</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">GraalVM</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">High</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Python</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">JavaCC</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">High</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">x86/x64</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Ghidra</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">High</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">JVM Bytecode</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Soot</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Kotlin</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">IntelliJ PSI</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">PHP</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">PHP-Parser</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Go</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">go.parser</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Ruby</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">ANTLR</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium-Low</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Swift</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">SwiftSyntax</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium</td></tr><tr style="border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">C#</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Roslyn</td><td style="border-color: rgb(223, 223, 223);line-height: 1.75;font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;">Medium-Low</td></tr></tbody></table>  
## joern-cli  
  
joern-cli 是我们用来构建代码属性图和进行查找的套件，可以在 github 下载 release 版本的   
joern-cli.zip  
[3]，也可以通过自行编译的方式构建。  
  
后续写复杂规则需要自动补全，以及需要搜索代码查看用例，因此推荐通过源代码方式编译：  
```
git clone https://github.com/joernio/joern
cd joern
sbt stage
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtmuVIq6tF1RoRfCtYos9BQQQoAprG7jeJtvI9PSqic7LSr71bb0NfY16G0Jw3hNd7ZexggP1Yn6BL1LHEPXqIw/640?wx_fmt=png&from=appmsg "")  
  
安装完成后可以进行实际测试，使用一个简单的 Java 文件 Hello.java 如下：  
```
package demo;

import a.b.c.Foo;

public class Hello {
  static Foo foo = new Foo();

  public static void main(String[] args) {
    String data = foo.bar(args[0]);
    Runtime.exec(data);
  }
}
```  
  
将该源码文件构建成代码属性图数据库(cpg)可以使用 joern-parse 脚本：  
```
joern-parse --language javasrc Hello.java -o hello.cpg
```  
  
有几个注意点：  
1. 1. language 选择的是 javasrc 而不是 java，后者是 Soot 的前端；  
  
1. 2. 可以使用 joern-parse --list-languages 列举所有支持的前端(语言)；  
  
1. 3. Hello.java 中包含外部类 a.b.c.Foo，因此实际无法编译，但是却可以正确生成 cpg；  
  
对该 cpg 进行查询：  
```
joern hello.cpg
joern> cpg
val res0: io.shiftleft.codepropertygraph.generated.Cpg = Cpg[Graph[136 nodes]]
# ...
joern> def source = cpg.method("main").parameter
joern> def sink = cpg.call("exec").argument
joern> sink.reachableByFlows(source).p
val res7: List[String] = List(
  """┌─────────────────┬──────────────────────────────┬────┬──────┬────┐│nodeType         │tracked                       │line│method│file│├─────────────────┼──────────────────────────────┼────┼──────┼────┤│MethodParameterIn│main(String[] args)           │8   │main  │    ││Call             │demo.Hello.foo.bar(args[0])   │9   │main  │    ││Call             │demo.Hello.foo.bar(args[0])   │9   │main  │    ││Call             │demo.Hello.foo.bar(args[0])   │9   │main  │    ││Identifier       │String data = foo.bar(args[0])│9   │main  │    ││Identifier       │Runtime.exec(data)            │10  │main  │    │└─────────────────┴──────────────────────────────┴────┴──────┴────┘"""
)
```  
  
核心的查询就三行，查找从 main 的参数到 Runtime.exec 的参数中的数据流链路：  
```
def source = cpg.method("main").parameter
def sink = cpg.call("exec").argument
sink.reachableByFlows(source).p
```  
  
其中 cpg 是我们的代码属性图根对象，针对代码的查找都基于此对象出发进行查询。上面的查询语句实际上是合法的 scala 语句，joern-cli 本身也是一个 scala 解释器。除了 cpg 对象，还定义了一些全局的对象和方法，可以使用 help 进行查看：  
```
joern> help
val res8: Helper = Welcome to the interactive help system. Below you find
a table of all available top-level commands. To get
more detailed help on a specific command, just type

`help.<command>`.

Try `help.importCode` to begin with.
┌────────────────┬────────────────────────────────────────────────┬─────────────────────────┐
│command         │description                                     │example                  │
├────────────────┼────────────────────────────────────────────────┼─────────────────────────┤
│close           │Close project by name                           │close(projectName)       │
│cpg             │CPG of the active project                       │cpg.method.l             │
│delete          │Close and remove project from disk              │delete(projectName)      │
│exit            │Exit the REPL                                   │                         │
│importCode      │Create new project from code                    │importCode("example.jar")│
│importCpg       │Create new project from existing CPG            │importCpg("cpg.bin.zip") │
│open            │Open project by name                            │open("projectName")      │
│openForInputPath│Open project for input path                     │                         │
│project         │Currently active project                        │project                  │
│run             │Run analyzer on active CPG                      │run.securityprofile      │
│save            │Write *all changes to disk                       │save                     │
│switchWorkspace │Close current workspace and open a different one│                         │
│workspace       │Access to the workspace directory               │workspace                │
└────────────────┴────────────────────────────────────────────────┴─────────────────────────┘

joern> cpg.help
...
```  
  
joern-cli 套件除了 joern-parse 和 joern，还包含了 joern-export、joern-scan 等脚本用户导出控制流图以及批量扫描等功能，关于这些工具的使用细节，可以参考官方的   
Joern Documentation  
[4]。  
## Steps  
  
以 cpg 为根结点，我们可以查找代码属性图中的所有结点类型，比如类、方法、调用、控制流等。这些结点都可以以属性的形式获取，比如：  
- • cpg.method: 表示所有方法结点；  
  
- • cpg.parameter: 表示所有方法的参数；  
  
- • cpg.method("main").parameter: 表示所有名称为 main 的方法的参数；  
  
- • cpg.typeDecl("Foo").method: 表示所有名称为 Foo 的类中的所有方法；  
  
其中以 cpg.method 为例，其返回值是 Iterator[Method] 类型，因此可以调用所有 Scala   
Iterator  
[5] 的方法，比如 map、filter、toList、size、head 等，后文介绍 Scala 时会也会提及。  
  
cpg.method.parameter 实际上是拓展了 Iterator，使其支持子查询。另外 Joern 还实现了一些特殊的 Step 比如用于递归查询的 repeat、times 系列和用于数据流分析的 sink.reachableBy(source) 系列。  
  
所有类型的 Step 可以参考文档中的   
Node-Type Steps  
[6] 一节。  
# Scala 101  
  
前面说过，Joern 使用 Scala 编写，而且其查询语句也是 Scala 语句，因此为了熟悉 Joern 的查询，我们有必要先简单学习一下 Scala。很多同学没用过 Scala，因此一看到就觉得它像 Lisp、Haskell 一样反人类，但其实这是一个很简单的语言。  
  
Scala 是一种基于 JVM 的语言，也就是说 .scala 源码可以像 Java 一样编译为 .class 文件，同时被 JVM 加载运行。其实可以将 Scala 当成是一个 Java 的拓展，可以使用现有的 Java 生态。如果你用过 Kotlin，那么应该会对 Scala 的语法感到熟悉。  
- •   
Scala Install  
[7]  
  
- •   
Scala Getting Start  
[8]  
  
- •   
Scala Cheatsheet  
[9]  
  
## HelloWorld  
  
一个简单的 hello.scala 代码如下：  
```
object hello {
  def main(args: Array[String]) = {
    println("Hello, World!")
  }
}
```  
  
如果是 Scala3，则可以更简单：  
```
@main def hello() = println("Hello, World!")
```  
  
编译运行：  
```
scalac hello.scala
scala hello
```  
## 语法速通  
  
本节主要介绍一些 Joern 查询经常用到的语法。  
  
首先是变量定义：  
```
var a = 1
val b = List(1, 2)
val c = 1 to 5 // 表示 1 到 5 的 Iterator
```  
  
可以看到 Scala 虽然是个强类型语言，但是可以做到智能类型推导，因此在变量赋值的时候通常无需指定类型。  
  
函数定义：  
```
def fn(x: Any) = println(x)
def fn1(x: Int) = { x * x }
def fn2 = 1 to 5
```  
  
对于函数定义来说，所有的参数还是需要声明类型的，不过返回类型可以自动推导得到。  
> 注意 def a = 1 to 5 和 val a = 1 to 5 的差异，两者都是返回 Iterator 对象，但是前者每次返回都是新的 Iterator，而后者指向同一个 Iterator，因此后者只能遍历一次。  
  
  
匿名函数和 JavaScript 类似，可以写成箭头函数 (x: R) => x * x，常用于需要传入过滤函数的场景，比如：  
```
def it = 1 to 5
it.map(x => x * 2)
// 对于单个函数参数，可以省略括号
it.map { x =>
  val y = x * 2
  println(y)
  y
}
// 可以使用 `_` 代替单个参数：
it.map(_ * 2)
```  
  
Scala 中有一些特别的语法糖，比如中缀语法糖：  
```
case class Pair(x: Int, y: Int) {
  def plus(other: Pair): Int = x + other.x + y + other.y
}

val p1 = Pair(1, 2)
val p2 = Pair(3, 4)
val sum = p1 plus p2  // 使用中缀语法
// 等价于
val sum = p1.plus(p2)
```  
  
因此下面两个表达式也是等价的：  
```
5 + 3
5.+(3)
```  
  
按照惯例，如果你调用方法是为了利用方法的“副作用”，此时写上空括号，如果方法没有任何副作用（没有修改其它程序状态），你可以省略掉括号。  
```
(1 to 5).toList()
// 一般写成
(1 to 5).toList
```  
  
类定义方面，普通类和抽象类和 Java 中的定义类似，接口则和 Rust 比较类似，用 trait 定义：  
```
trait MyTrait {
  def method(): Unit = println("This is a trait method.")
}
```  
  
案例类，用于生成不可变的数据接口，自动生成 apply、unapply、toString、equals 等方法：  
```
case class MyCaseClass(name: String, age: Int)
```  
  
对象类，也称单例类，只能有一个实例：  
```
object MyObject {
  def method(): Unit = println("yeah.")
}
```  
  
基本的语法也就这样了，更多 Scala 的语法和使用细节可以通过阅读 Joern 或其他项目的源码去熟悉(使用 Scala 的项目有 Apache Spark、Kafka、Flink 等)。毕竟语言只是一种工具，多看多写才能有所进步。  
## sbt  
  
和 Java 使用 maven 进行工程管理一样，Scala 一般使用   
sbt  
[10] 进行工程管理。有趣的是 sbt 的管理文件 build.sbt 也是使用 Scala 编写的，一个示例如下：  
```
ThisBuild / scalaVersion := "2.13.12"
ThisBuild / organization := "com.example"

lazy val hello = project
  .in(file("."))
  .settings(
    name := "Hello",
    libraryDependencies += "org.scala-lang" %% "toolkit-test" % "0.1.7" % Test
  )
```  
  
sbt 可以和 maven 一样通过模版新建工程：  
```
sbt new scala/scala-seed.g8
```  
  
编译测试运行：  
```
sbt compile
sbt test
sbt clean run
```  
  
Joern 的工程同样是通过 sbt 进行管理，因此了解 sbt 有助于我们后续理解其架构和阅读源码。更多的 sbt 功能参考官方文档 https://www.scala-sbt.org/ 。  
# 实战分享  
  
学习了 Joern 的基本代码属性图和 Scala 的语法，现在可以开始编写你的第一条代码分析规则了！本节列举一些常用查询示例，以便大家熟悉 Joern 查询的风格。  
  
我们使用两个不同的项目进行测试，分别是一个 Spring 源码应用，以及一个 Android 应用。  
```
joern
joern> importCode("vuln-spring")
joern> importCode("xiaomi.apk")
```  
  
同一个 joern-cli 可以加载多个项目，通过 workspace 命令查看所有 project，通过 workspace.openProject 打开对应的工程。  
  
在代码图属性数据层来说，具体的查找是语言无关的，不过某些 Step 只有在特定语言才会生效(比如 annotation)，因此具体选择的语言关系并不大，你也可以用 C/C++ 或者 Python 和 JavaScript 项目来进行测试。  
## Web 漏洞挖掘  
  
vuln-spring  
[11] 是一个 Spring Web 应用，对于这类项目，可能我们第一个想要找的就是路由：  
```
cpg.annotation.where(_.name(".*Mapping")).method.fullName.l
```  
  
这个查询应该还算比较直观，有个需要注意的是 where，它和 filter 的主要不同点在于前者过滤函数的返回值为 Iterator 类型，而 filter 的过滤函数需要返回 Boolean 类型。末尾的 .l 实际上是 .toList 的简写(alias)，即将 Iterator 转换为 List 进行输出。  
  
然后是找漏洞点，比如 SQL 注入。这里以 springframework   
JdbcTemplate  
[12] 为例，查找其类方法。  
  
根据直觉很容易写入下面的查询：  
```
cpg.typeDecl.fullNameExact("org.springframework.jdbc.core.JdbcTemplate").method.l
```  
  
其中 fullNameExcat 是一个快捷方法，相当于 typeDecl.filter(_.fullName.equals("xx"))。前面查询用到的 name("xxx") 也是类似的实现。以 name 为例，常用的简写包括：  
- • nameExact("xxx"): 等于；  
  
- • name("xxx"): 正则表达式匹配；  
  
- • nameNot("xxx"): 不等于，也是正则匹配；  
  
.filter 和 .where 也包括类似的 filterNot 和 whereNot 快捷取反匹配。  
  
但是，上面的查询实际上会返回空列表，因为 JdbcTemplate 这个类并不是定义在代码中的，而是在 Spring 的 jar 包中外部类。我们构建 CPG 数据库的时候并没有获取依赖，因此自然也就无法得知该类下的所有方法。  
  
这是新手很容易犯的错误，不过只要了解原理就很容易避免，正确查找外部方法的方式是：  
```
cpg.method.fullName("org\\.springframework\\.jdbc.core\\.JdbcTemplate\\..*")
// 或者
cpg.method.filter(_.fullName.startsWith("org.springframework.jdbc.core.JdbcTemplate."))
// 或者更用的，直接找调用
cpg.call.filter(_.methodFullName.startsWith("org.springframework.jdbc.core.JdbcTemplate.")).code.l
```  
  
将 source 和 sink 组合起来，就写出了我们第一条 SQL 注入查询规则：  
```
def source = cpg.annotation.where(_.name(".*Mapping")).method.parameter
def sink = cpg.call.filter(_.methodFullName.startsWith("org.springframework.jdbc.core.JdbcTemplate.")).argument(1)
sink.reachableByFlows(source).p
```  
  
.p 和 .l 一样是一个快捷方法，用于将 Iterator 以格式化文本的方式输出。上面的结果有部分误报，主要是指定了所有路由参数，其中包含一些不可控的 Model 或者 HttpSession 对象，可以进一步优化规则进行约束。  
  
注意这里 sink 指定 argument(1) 表示第一个参数，argument(0) 一般表示方法调用的 this 对象。  
  
sink.reachableBy(source) 返回的则是满足条件的 source，对于我们的查询而言是 Iterator[MethodParameterIn]；reachableByFlows 返回的是 Iterator[Path]，.p 会将其以表格的形式打印，如果你不喜欢默认的表格输出，也可以通过 map 方式转换为自定义的输出。  
```
def prettyPath = (p: Path) => p.elements.map(
 e => String.format("%-20s %s", e.label, e.code)
).mkString("\n")
sink.reachableByFlows(source).map(prettyPath).mkString("\n\n===\n")
```  
  
mkString 相当于 String.join 方法，将列表组合为字符串。输出示例：  
```
METHOD_PARAMETER_IN  @RequestParam(name = "password", required = true) String password
IDENTIFIER           password          
METHOD_PARAMETER_IN  String password     
IDENTIFIER           password                       
CALL                 "SELECT * FROM users WHERE USERNAME=\"" + username + "\" AND PASSWORD=\"" + password + "\""
IDENTIFIER           query         
```  
  
通过这种方式我们可以结构化漏洞扫描输出，形成报告或者对接其他的后续验证逻辑。  
## Android 漏洞挖掘  
  
与 Java 源码不同，有的 Jar 包只有字节码，不过 Joern 同样支持使用 Soot 去加载字节码并转换为 IR 从而将代码属性图存入数据库中。既然都是使用 Soot，那 Joern 是否支持 Android 漏洞扫描呢，答案是肯定的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3eicVGzibzClCnNR7ibAPTc7qsdjYfQO0lC6aIyB8PXtBqQjvlVvib6VEenrf8heAmzohErlV0MAYGiaTUFKZQN2AzQ/640?wx_fmt=png&from=appmsg "给 Joern 的第一个 PR")  
  
给 Joern 提的第一个 PR  
  
对于小型 APK 可以直接使用 jimple2cpg 或者 importCode 默认参数进行加载，而对于大型应用最好添加 --android 参数指定 android.jar (这是 Soot 的 API 导致的 Bug)。同时对于大型应用需要适当提高 JVM 内存。  
```
jimple2cpg -J-Xmx30g --android $ANDROID_HOME/platforms/android-34/android.jar large.apk -o large.cpg
```  
  
如果大家想要练手，可以使用一些开源的漏洞靶标应用进行测试，比如：  
- •   
oversecured/ovaa  
[13] 可以在这里下载   
ovaa-debug.apk  
[14]  
  
- •   
DIVA Android  
[15]  
  
- •   
awesome-vulnerable-apps  
[16]  
  
这里我们以一个实际漏洞为案例进行分析，即小米去年的一个系统应用命令注入漏洞。  
  
漏洞详情可以参考 Oversecured 的博客   
20 Security Issues Found in Xiaomi Devices  
[17]，本节复现的是其中一个 System Tracing 应用的命令注入漏洞。对应的 APK 可以在 apkmirror 下载，见   
System Tracing 1.0  
[18]。  
  
该漏洞原理在于小米动态注册了一个 AppReceiver，并且在其 onReceive 方法中通过接收的参数拼接 shell 命令执行导致命令注入。  
  
对于漏洞挖掘而言，我们自动化挖掘该漏洞的难点在哪呢？首先在 Android 的四大组件中，BroadCastReceiver 比较特殊，它是唯一一个可以不用在 AndroidManifest.xml 中定义也可以使用的组件，即通过动态注册的方式初始化。  
  
那么我们首要的任务就是找到所有代码中的 BroadCastReceiver 找出来，这个需求比较简单：  
```
cpg.typeDecl.fullNameExact("android.content.BroadcastReceiver").derivedTypeDeclTransitive.fullName.l
```  
  
derivedTypeDecl 及其变种 derivedTypeDeclTransitive 都是用于查找子类的辅助方法，如果自己写的话可以通过递归解析和查找 inheritsFromTypeFullName 属性来查找接口和父类。  
  
这个查询只是找到所有 Receiver，但并不一定都有用到，所以我们进一步通过   
Context.registerReceiver  
[19] 查找实际注册的 Receiver 对象，并定位到实际的类型。  
  
我们可以利用 Joern 数据流分析的能力，查找 BroadcastReceiver 的构造方法调用到 registerReceiver 的数据流，如下所示：  
```
val baseCls = "android.content.BroadcastReceiver"
val receiverCls = cpg.typeDecl.fullNameExact(baseCls).derivedTypeDeclTransitive.fullName.l
def source = cpg.call.nameExact(Operators.alloc).filter(n => receiverCls.contains(n.typeFullName))
def sink = cpg.call.nameExact("registerReceiver").argument(1)

// 查找数据流
sink.reachableBy(source)
```  
  
这个查询能够找到类似下面这种调用：  
```
BroadcastReceiver r = new FooReceiver();
this.registerReceiver(r, filter);
```  
  
但是却找不到我们这个漏洞所处于的位置，反编译代码：  
```
public class ApplicationImpl extends Application {  
    private AppReceiver mDumpReceiver = new AppReceiver();  
  
    @Override // android.app.Application  
    public void onCreate() {  
        super.onCreate();  
        IntentFilter intentFilter = new IntentFilter();  
        intentFilter.addAction("com.android.traceur.DumpReceiver");  
        registerReceiver(this.mDumpReceiver, intentFilter);  
    }
}
```  
  
这里实际上是通过属性的方式进行传递，可以看到 Joern 的数据流分析这里并没有关联上，因为 source 和 sink 分别在两个不相关的函数 <clinit> 和 onCreate() 中，静态分析工具并不知道 onCreate 这种生命周期函数什么时候会被调用。  
  
一种方式是修改 Joern 的前端代码，模拟 Runtime 进行生命周期方法调用，在解析代码属性图的时候为这些方法添加自定义的调用，从而补全增强控制流图(CFG)。  
  
当然这种方式可能需要修改 Joern 源码，我们可以通过其他投机取巧的方式，观察到 source 和 sink 的连结断点主要在类属性上，那么可以尝试新建一个中间结点再做一次数据流分析。  
```
def fieldAccess = cpg.fieldAccess.filter(fa => receiverCls.contains(fa.typeFullName) || fa.typeFullName.equals(baseCls))
// 所有 BroadCastReceiver 及其子类类型的属性读取结点
def fieldRead = fieldAccess.filter(fa => fa.argumentIndex == 2)
// 返回的是实际的 BroadCastReceiver 类型的属性
val reads = sink.reachableBy(fieldRead).toList
// 找到所有的属性名称，结果为 List[List[String]]
val fields = reads.map(r => List(r.typeDecl.fullName.head, r.fieldIdentifier.canonicalName.head))
// 匹配上述 field 的所有写入
def fieldWrite = fieldAccess
  .filter(fa => fa.argumentIndex == 1)
  .filter{fa =>
    val li = fa.map( r =>
        List(r.typeDecl.fullName.head, r.fieldIdentifier.canonicalName.head)
    )
    li.exists(fields.contains)
  }

// 数据流查询
fieldWrite.reachableByFlows(source).p
```  
  
稍微解释一下：  
1. 1. fieldAccess.argumentIndex 表示属性在上级表达式中的参数位置，1 为写入，类似 r0.field = value，2 为读取，类似 r1 = r0.field；这个指定不是必须的，不过在代码量大的时候可以稍微提升下速度；  
  
1. 2. fieldAccess 包含所有类型为 BroadCastReceiver 及其子类的属性的访问，注意 receiverCls 中只包含子类，没包含 BroadCastReceiver 父类本身，因此需要加上以匹配多态的情况；  
  
1. 3. fields 是为了拿到所有的属性字段名称，以 List 的格式存储，包含类名和字段名，用字符串保存也是可以的；  
  
1. 4. 然后在 fieldWrite 匹配对应字段的写入，这里使用了 List.exists 判断列表 li 中是否包含列表 fields 中的元素；  
  
最后使用 reachableByFlows 找到所有原 source 到指定属性写中的链路，返回结果如下：  
```
joern> fieldWrite.reachableByFlows(source).p
val res131: List[String] = List(
  """┌──────────────────┬──────────────────────────────────────────────────┬────┬────────┬────────────────────────────────┐│nodeType          │tracked                                           │line│method  │file                            │├──────────────────┼──────────────────────────────────────────────────┼────┼────────┼────────────────────────────────┤│Call              │new com.android.traceur.MainFragment$10           │228 │onCreate│com.android.traceur.MainFragment││Identifier        │$r17 = new com.android.traceur.MainFragment$10    │228 │onCreate│com.android.traceur.MainFragment││Identifier        │$r17.com.android.traceur.MainFragment$10(r0)      │228 │onCreate│com.android.traceur.MainFragment││MethodParameterIn │<init>(this, com.android.traceur.MainFragment $r1)│227 │<init>  │com.android.traceur.MainFragment││MethodParameterOut│RET                                               │227 │<init>  │com.android.traceur.MainFragment││Identifier        │$r17.com.android.traceur.MainFragment$10(r0)      │228 │onCreate│com.android.traceur.MainFragment││Identifier        │r0.mRefreshReceiver = $r17                        │228 │onCreate│com.android.traceur.MainFragment││Call              │r0.mRefreshReceiver = $r17                        │228 │onCreate│com.android.traceur.MainFragment│└──────────────────┴──────────────────────────────────────────────────┴────┴────────┴────────────────────────────────┘""",
  """┌──────────────────┬─────────────────────────────────────────┬────┬──────┬───────────────────────────────────┐│nodeType          │tracked                                  │line│method│file                               │├──────────────────┼─────────────────────────────────────────┼────┼──────┼───────────────────────────────────┤│Call              │new com.android.traceur.AppReceiver      │8   │<init>│com.android.traceur.ApplicationImpl││Identifier        │$r1 = new com.android.traceur.AppReceiver│8   │<init>│com.android.traceur.ApplicationImpl││Identifier        │$r1.com.android.traceur.AppReceiver()    │8   │<init>│com.android.traceur.ApplicationImpl││MethodParameterIn │<init>(this)                             │38  │<init>│com.android.traceur.AppReceiver    ││MethodParameterOut│RET                                      │38  │<init>│com.android.traceur.AppReceiver    ││Identifier        │$r1.com.android.traceur.AppReceiver()    │8   │<init>│com.android.traceur.ApplicationImpl││Identifier        │r0.mDumpReceiver = $r1                   │8   │<init>│com.android.traceur.ApplicationImpl││Call              │r0.mDumpReceiver = $r1                   │8   │<init>│com.android.traceur.ApplicationImpl│└──────────────────┴─────────────────────────────────────────┴────┴──────┴───────────────────────────────────┘"""
)
```  
  
找到了两个匹配，其中第二个即为我们要找的漏洞类，第一个结果匹配的点为：  
```
public class MainFragment extends PreferenceFragment {
 // ...
 private BroadcastReceiver mRefreshReceiver;
 @Override // androidx.preference.PreferenceFragment, android.app.Fragment
    public void onCreate(Bundle bundle) {
     // ...
     this.mRefreshReceiver = new BroadcastReceiver() { // from class: com.android.traceur.MainFragment.10
            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context, Intent intent) {
                MainFragment.this.refreshUi();
            }
        };
    }
 @Override // androidx.preference.PreferenceFragment, android.app.Fragment
    public void onStart() {
        super.onStart();
        // ...
        getActivity().registerReceiver(this.mRefreshReceiver, new IntentFilter("com.android.traceur.REFRESH_TAGS"), 4);
        Receiver.updateTracing(getContext());
    }
}
```  
  
可以看到我们这个查询语句同样也找到了基于多态的匿名类赋值，其中动态注册的类名为 com.android.traceur.MainFragment$10。虽然规则写得有点 ugly，不过已经基本能用了。  
  
后续操作就是要继续添加规则，将两种不同的数据流合并，然后将 source 中的构造方法对应类名提取出来，再定位其 onReceive 方法，将该方法的参数作为后续阶段漏洞分析的 source，从而查找到危险函数如 Runtime.exec 等的调用。  
# 进阶操作  
  
从前面的分享中应该已经基本了解了 Joern 的用法和常见查询，同时也知道该工具存在一些局限性。幸运的是 Joern 同时也存在很强的拓展性，本节就来介绍一些比较有用的拓展操作。  
## 数据流语义  
  
在前面介绍 Web 漏洞挖掘时，我们的 SQL 查询实际上有很多误报，其中最为严重的一个误报是明明指定了 sink 是 JdbcTemplate 的方法第一个参数，但实际上参数传入了其他参数也会认为是有效路径：  
```
def sink = cpg.call.filter(_.methodFullName.startsWith("org.springframework.jdbc.core.JdbcTemplate.")).argument(1)
```  
  
这是因为 Joern 对于没有代码的外部方法，为了保持可靠性(soundness)，会将这些方法的传播规则设置为交叉传播到所有参数和返回值，牺牲误报率以减少漏报率。  
  
这无疑提高了我们分析误报的成本。那么有没有什么方法可以优化数据流分析，即对指定方法进行语义配置呢？答案是有的。我们可以指定额外的 FlowSemantic 列表，如下所示：  
```
import io.joern.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import io.joern.dataflowengineoss.semanticsloader.FlowSemantic

val extraFlows = List(
    FlowSemantic.from(
        "^path.*<module>\\.sanitizer$", // Method full name
        List((1, 1)), // Flow mappings
        regex = true  // Interpret the method full name as a regex string
    )
)

val context = new LayerCreatorContext(cpg)
val options = new OssDataFlowOptions(extraFlows = extraFlows)
new OssDataFlow(options).run(context)
```  
  
数据流映射通过数字 Tuple 实现：  
- • 1, -1 表示第一个参数数据流会传播给返回值；  
  
- • 1, 2 表示第一个参数数据流会传播给第二个参数；  
  
- • 1, 0 表示第一个参数数据流会传播给示例对象(this)；  
  
- • 1, 1 表示第一个参数数据流会传播给自身，通常用于表示数据流是否中断，即用于指定 sanitizer；  
  
比如如下代码：  
```
x = source()
foo(x) // "foo" 1->1 表示数据流继续向下传播，否则会中断
sink(x)
```  
  
除了以上面的代码形式指定，Joern 也支持使用   
semanticsloader/Parser  
[20] 加载语义文件，每行表示一条 extraFlows，包含多个 FlowSemantic，以空格分隔，例如：  
```
"foo" 1->-1 2->3
```  
  
每个参数都需要带有位置标识，不过对于某些语言可以指定命名参数：  
```
"foo" 1 "param1"->2 3 -> 2 "param2"
```  
  
对于一般的数据流分析，会认为默认参数间不互相污染，并且参数会污染返回值。因为大家写得比较多，所以 Joern 也提供了特殊的规则即 PASSTHROUGH:  
```
"foo" PASSTHROUGH 0 -> 0
```  
  
使用 scala 代码为：  
```
FlowSemantic("foo", List(PassThroughMapping))
```  
  
从语义上来说等价于 foo(1, 2) = 1 -> 1, 2 -> 2, 1 -> -1, 2 -> -1，即所有参数会污染自身和函数的返回值，注意没有 0 -> 0，因此 this 对象不会污染自身。  
  
我们可以通过 context.semantics.elements 查看当前默认的 FlowSemantic 列表。前面添加语义使用的 val context = new LayerCreatorContext(cpg) 会覆盖当前的 context 对象。  
  
从实践上来看，创建语义的方式有多种，可以自行选取适合的方式：  
```
import io.joern.dataflowengineoss.semanticsloader.{FlowSemantic, PassThroughMapping, Parser}
// 调用构造方法
val s = FlowSemantic("org\\.springframework.*", List(PassThroughMapping), true)
// 调用静态方法
val s = FlowSemantic.from("org\\.springframework.*", List((1, -1)), true)
// 使用 Parser
val parser = Parser()
// 从字符串加载单条或者多条语义，返回列表
val extraFlows = parser.parse(""" "foo" PASSTHROUGH 0 -> 0 """)
// 从文件中加载
val extraFlows = parser.parseFile("semantics.txt")
```  
  
更多细节可以查看官方的文档介绍   
Dataflow Semantics  
[21] 或者查看源码。  
## 控制流增强  
  
不同于数据流分析，有时候我们仅仅关注控制流，比如下面的语句可以递归查找调用：  
```
cpg.method.name("exec").repeat(_.caller)(_.emit.dedup).fullName.sorted
```  
  
对于我们之前 Android 漏洞挖掘的例子，数据流分析在面对 Android 运行时的一些回调函数时无法进行跟踪，本质也是因为控制流没有关联上。由于 Joern 本身是基于 Scala 的查询，而且也把所有数据结构暴露给了用户，那其实也可以像自定义数据流语义一样添加新的控制流规则。  
  
伪代码如下：  
```
val methods = cpg.method
val node1 = methods.next
val node2 = methods.next
node1.addEdge(EdgeTypes.AST, node2)
```  
  
可基于 joern-cli 的自动补全查看支持的边类型：  
```
joern> EdgeTypes.
ALIAS_OF             AST                  CALL                 CDG                  CONTAINS             IMPORTS              PARAMETER_LINK       REACHING_DEF         SOURCE_FILE
ALL                  BINDS                CAPTURE              CFG                  DOMINATE             INHERITS_FROM        POINTS_TO            RECEIVER             TAGGED_BY
ARGUMENT             BINDS_TO             CAPTURED_BY          CONDITION            EVAL_TYPE            IS_CALL_FOR_IMPORT   POST_DOMINATE        REF
```  
  
这是旧版本的用法，新版本中使用 diffGraph 对象，类型为 DiffGraphBuilder，使用 diffGraph.addEdge 可以直接新增控制流边。  
  
考虑一个最常见的多线程调用场景：  
```
class ThreadDemo {
  public static void main(String args[]) throws Exception {
    final String cmd = String.format("sh -c \"%s\"", args[0]);
    Thread th = new Thread(new Runnable() {
      @Override
      public void run() {
        System.out.println("Running in a new thread");
        try {
          System.out.println("return: " + Runtime.getRuntime().exec(cmd));
        } catch(Exception ignore) {}
      }
    });
    th.start();
    Thread.sleep(1000);
  }
}
```  
  
正如前面所说，如果使用正常的静态分析，是无法识别到输入到输出的数据流的：  
```
def source = cpg.method.nameExact("main").parameter
def sink = cpg.call.nameExact("exec").argument
sink.reachableBy(source)
```  
  
针对这个用例，我们需要让程序知道 Thread.start 会调用到 Runnable.run，因此可以直接添加一条边：  
```
val call = cpg.call("start").head
val target = cpg.method("run").head
diffGraph.addEdge(call, target, EdgeTypes.CALL)
run.commit
```  
  
然后再运行 sink.reachableBy 就能找到正确的调用链了：  
```
joern> sink.reachableByFlows(source).p
val res4: List[String] = List(
  """                                                                                                                  ┌──────────────────┬────────────────────────────────────────────────────────────────────────────┬────┬──────┬────┐     │nodeType          │tracked                                                                     │line│method│file│   ├──────────────────┼────────────────────────────────────────────────────────────────────────────┼────┼──────┼────┤│MethodParameterIn │main(String[] args)                                                         │2   │main  │    ││Call              │<operator>.arrayInitializer                                                 │3   │main  │    ││Call              │<operator>.arrayInitializer                                                 │3   │main  │    ││Call              │String.format("sh -c \"%s\"", args[0])                                      │3   │main  │    ││Identifier        │String cmd = String.format("sh -c \"%s\"", args[0])                         │3   │main  │    ││Identifier        │new Runnable() { @Override public void run() { System.out.println("Running  │4   │main  │    │
│                  │in a new thread"); try { System.out.println("return: " +                    │    │      │    ││                  │Runtime.getRuntime().exec(cmd)); } catch (Exception ignore) { } } }         │    │      │    ││MethodParameterIn │<init>(this, cmd)                                                           │4   │<init>│    ││Identifier        │this.cmd = cmd                                                              │4   │<init>│    ││Call              │this.cmd = cmd                                                              │4   │<init>│    ││MethodParameterOut│RET                                                                         │N/A │<init>│    ││Identifier        │new Runnable() { @Override public void run() { System.out.println("Running  │4   │main  │    │
│                  │in a new thread"); try { System.out.println("return: " +                    │    │      │    ││                  │Runtime.getRuntime().exec(cmd)); } catch (Exception ignore) { } } }         │    │      │    ││Block             │$obj0                                                                       │4   │main  │    ││Identifier        │new Thread(new Runnable() { @Override public void run() {                   │4   │main  │    ││                  │System.out.println("Running in a new thread"); try {                        │    │      │    ││                  │System.out.println("return: " + Runtime.getRuntime().exec(cmd)); } catch    │    │      │    ││                  │(Exception ignore) { } } })                                                 │    │      │    ││Identifier        │th.start()                                                                  │13  │main  │    ││MethodParameterIn │run(this)                                                                   │5   │run   │    ││Call              │Runtime.getRuntime().exec(cmd)                                              │9   │run   │    │└──────────────────┴────────────────────────────────────────────────────────────────────────────┴────┴──────┴────┘""",
```  
  
注意 diffGraph 只是一个临时的差分图，需要 commit 之后才能将差异提交到 cpg 中。这只是一种简单的示例，代码中还没关联 Thread 对应的具体 Runable 类，这就留给读者进行完善了。  
  
如果需要对代码属性图做复杂的操作，比如针对反射实现数据流跟踪等，可以使用自定义 Pass，参考下一节的介绍。  
## CpgPass  
  
前面我们提到了 diffGraph，笔者其实是通过搜索代码找到的，发现在 ghidra2cpg 的   
JumpPass.scala  
[22] 中就有类似的操作：  
```
class JumpPass(cpg: Cpg) extends ForkJoinParallelCpgPass[Method](cpg) {

  override def generateParts(): Array[Method] =
    cpg.method.toArray
  override def runOnPart(diffGraph: DiffGraphBuilder, method: Method): Unit = {
    method.ast
      .filter(_.isInstanceOf[Call])
      .map(_.asInstanceOf[Call])
      .nameExact("<operator>.goto")
      .where(_.argument.order(1).isLiteral)
      .foreach { sourceCall =>
        sourceCall.argument.order(1).code.l.headOption.flatMap(parseAddress) match {
          case Some(destinationAddress) =>
            method.ast.filter(_.isInstanceOf[Call]).lineNumber(destinationAddress).foreach { destination =>
              diffGraph.addEdge(sourceCall, destination, EdgeTypes.CFG)
            }
          case _ => // Ignore for now
          /* TODO: Ask ghidra to resolve addresses of JMPs */
        }
      }
  }

  private def parseAddress(address: String): Option[Int] = {
    Try(Integer.parseInt(address.replaceFirst("0x", ""), 16)).toOption
  }
}
```  
  
Pass 是 Joern 中用于后处理 CPG 图数据库的结点，比如生成 CFG(Control Flow Graph) 和 DDG(Data Dependency Graph) 等。  
  
针对上一节提到的控制流增强，笔者写了个简单的 DemoPass：  
```
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method, StoredNode, Type, TypeDecl}
import io.shiftleft.passes.CpgPass


class DemoPass(cpg: Cpg) extends CpgPass(cpg) {

  override def run(diffGraph: DiffGraphBuilder): Unit = {
    val call = cpg.call("start").head
    val target = cpg.method("run").head
    val targetNode = methodFullNameToNode(target.fullName).get
    diffGraph.addEdge(call, targetNode, EdgeTypes.CALL)
    println(s"Add Edge: $call -> $targetNode")
  }

  private def nodesWithFullName(x: String): Iterator[StoredNode] =
    cpg.graph.nodesWithProperty(PropertyNames.FULL_NAME, x).cast[StoredNode]

  private def methodFullNameToNode(x: String): Option[Method] =
    nodesWithFullName(x).collectFirst { case x: Method => x }
}
```  
  
通过以下方式加载：  
```
new DemoPass(cpg).createAndApply()
run.commit
```  
  
和 Pass 对应的是 Overlay，Joern 首次加载 CPG 或者使用 joern-parse 生成数据库的时候会默认执行一部分 pass，按照不同的层次依次执行。我们可以通过 project.appliedOverlays 查看当前生效的 Pass：  
```
joern> project.availableOverlays
joern> project.appliedOverlays
res0: Seq[String] = IndexedSeq("base", "controlflow", "typerel", "callgraph", "dataflowOss")
```  
  
以负责数据流分析的 dataflowOss 为例，其代码实现在   
OssDataFlow.scala  
[23]，会首先执行 ReachingDefPass，同时加上了 extraFlows 实现自定义的数据流控制。  
  
我们可以参考其代码实现自己的 Overlay 来增强 Joern 的功能，这也是其强拓展性的一个表现。  
## 其他  
  
在编写 Joern 代码查询规则的过程中，一个必备的知识就是需要了解其支持的 API，我们可以通过 joern-cli 的 help 命令查看 cpg 的具体 Step 以及后继支持的 Step 和简单介绍：  
```
cgp.help
cpg.method.help
cpg.typeDecl.help
```  
  
也可以通过下面的文档进行查阅：  
- •   
Node Type Steps - Reference Card  
[24] - 官方的文档；  
  
- •   
queries.joern.io  
[25] - joern-query 的示例查询规则；  
  
但不管是 joern-cli 的 help 命令还是官方文档，都没有完全覆盖所有的 Step，比如我们上面用到查询装饰的 annotation 和用于查询所有子类的 derivedTypeDecl。那么笔者是如何得知这些 API 的呢？一个方法是在社区里看别人的提问和回复，但这显然效率太低。另一个方法就是通过查询源码的方式找到这些信息。  
  
在 Joern 的主仓库   
joernio/joern  
[26] 中有许多单元测试，比如我们查看一些递归搜索的示例，可以搜索 .repeat( 从而查看具体选项例如 .emit、maxDepth 等用法。  
  
另外 Joern 的图数据库基座是   
joernio/flatgraph  
[27]，其前身是   
overflowdb  
[28]，最近 4.0 版本才完成切换。在该仓库中可以找到每个 Step 的实现。从中我们发现递归搜索 .repeat 默认为深度优先，可以通过 .bfs 设置为广度优先，等等诸如此类的 Trick。  
  
从代码中我们能找到一些比较实用的 Step，比如 collectAll 用于返回指定类型的节点。scala 中的 collect 相当于 filter+map 的结合：  
```
.collectAll[Call]
// 相当于
.collect { case x: Call => x }
// 相当于
.filter(_.isInstanceOf[Call]).map(_.asInstanceOf[Call])
```  
### 自定义 Step  
  
我们之前用到的这些 Step，其实也可以自定义，比如我们想要在 method 中新增一个 fooStep 查询，可以使用以下方法：  
```
implicit class MyMethodTraversals(method: Traversal[Method]) {
  def fooStep = method.fullName(".*org.example.*").isPublic
}

cpg.method.fooStep
```  
  
这使用了 Scala 的 implicit 隐式类类特性，用于通过隐式转换为现有类型添加新方法。隐式类通常用于增强现有类型的功能，而无需直接修改这些类型的定义。  
### 可视化  
  
有时编写规则的时候对于某些条件不太好判断，但是将全部结点打印出来又不直观，Joern 提供了一系列绘图方法可以打印指定结点的流图：  
```
joern> cpg.method("main").plotDot
plotDotAst     plotDotCdg     plotDotCfg     plotDotCpg14   plotDotDdg     plotDotPdg
```  
  
各种图的定义如下：  
- • AST: Abstract Syntax Tree，抽象语法树；  
  
- • CDG: Control Dependence Graph，控制依赖图，主要包含 if/else 等控制结构的依赖关系；  
  
- • CFG: Control Flow Graph，控制流图，程序执行的所有可能路径；  
  
- • DDG: Data Dependency Graph，数据依赖图，包含属于依赖关系；  
  
- • PDG: Program Dependence Graph，程序依赖图，包含控制依赖和数据依赖关系；  
  
plotDotXXX 会直接打开默认的图片预览工具，如果是没有图形界面的环境，可以通过 dotXXX 获取 dot 图片的 digraph 文本格式：  
```
cpg.method("main").dotAst.head #> "/tmp/main.dot"
```  
  
其中使用了自定义的操作符 #> 来将字符串重定向到文件中，也算是一个比较有用的小特性。还有其他用法就有待大家继续深入挖掘了。  
# 总结  
  
通过上面的分享，相信大家对 Joern 也有了比较直观的了解。先说说使用的缺点，首先是文档不完善，很多接口需要查看源代码或者在社区里找答案；另一个广为诟病的是其数据流引擎，存在很多误报和漏报的情况。上面的代码中看到它名字叫 ossdataflow，只实现了非常简单的数据流，和 CodeQL 等商业软件相比还有差距。这不禁让人想起隔壁村的 radare2，以及一张开源梗图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3eicVGzibzClCnNR7ibAPTc7qsdjYfQO0lCibgLPe9hSkv28Ped0et7xTyDdFaHOpZYh06RcAQSaMYc2ibyPOuDXgEQ/640?wx_fmt=png&from=appmsg "null")  
  
Open Source GNU/Car  
  
不过 Shiftleft(Joern 所属公司) 还有一款商业的代码扫描工具，名为 ocular，其中大部分功能和 joern 一致，只不过其数据流引擎是优化过的，而且增加了许多接口的建模，感兴趣的可以参考   
joern-vs-ocular  
[29]。由此可见不是没有能力做好，只是由于利益关系注定不会在上面投入太多。  
  
虽然有很多缺点，但 Joern 也有其优势。首先是其架构设计比较优雅，可以基于不同的前端加入新的语言支持，除了源码还支持字节码和二进制程序(汇编)；其次是其查询语言基于成熟的编程语言 Scala 来实现，具备很强的灵活性，可以实现各种复杂的查询；最后就是作为开源软件，主打一个 “自主可控”，只要具备一定编码能力那么基本各种需求都能够实现，从而克服前面说到的诸多缺点。  
# 参考资料  
- •   
Joern Website  
[30]  
  
- •   
Joern Blog  
[31]  
  
- •   
Node-Type Steps  
[32]  
  
- •   
ShiftLeftSecurity/codepropertygraph - CPG 标准、查询语言以及相关工具  
[33]  
  
- •   
ShiftLeftSecurity/overflowdb - 内存图数据库实现  
[34]  
  
- •   
joernio/flatgraph - 新版内存数据库 (overflowdb-v2)  
[35]  
  
- •   
docs.joern.io  
[36]  
  
#### 引用链接  
  
[1] Joern: https://joern.io/[2] CodeQL: https://codeql.github.com/[3] joern-cli.zip: https://github.com/joernio/joern[4] Joern Documentation: https://docs.joern.io/[5] Iterator: https://docs.scala-lang.org/overviews/collections/iterators.html[6] Node-Type Steps: https://docs.joern.io/cpgql/reference-card/[7] Scala Install: https://www.scala-lang.org/download/[8] Scala Getting Start: https://docs.scala-lang.org/getting-started/index.html[9] Scala Cheatsheet: https://docs.scala-lang.org/cheatsheets/[10] sbt: https://www.scala-sbt.org/1.x/docs/Running.html[11] vuln-spring: https://github.com/malikashish8/vuln-spring[12] JdbcTemplate: https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html[13] oversecured/ovaa: https://github.com/oversecured/ovaa[14] ovaa-debug.apk: https://github.com/dark-warlord14/ovaa[15] DIVA Android: https://github.com/payatu/diva-android[16] awesome-vulnerable-apps: https://github.com/vavkamil/awesome-vulnerable-apps?tab=readme-ov-file#mobile-security[17] 20 Security Issues Found in Xiaomi Devices: https://blog.oversecured.com/20-Security-Issues-Found-in-Xiaomi-Devices/#system-tracing---shell-command-injection[18] System Tracing 1.0: https://www.apkmirror.com/apk/xiaomi-inc/system-tracing-8/system-tracing-8-1-0-release/system-tracing-1-0-49-android-apk-download/[19] Context.registerReceiver: https://developer.android.com/reference/android/content/Context#registerReceiver(android.content.BroadcastReceiver,%20android.content.IntentFilter)[20] semanticsloader/Parser: https://github.com/joernio/joern/blob/master/dataflowengineoss/src/main/scala/io/joern/dataflowengineoss/semanticsloader/Parser.scala[21] Dataflow Semantics: https://docs.joern.io/dataflow-semantics/[22] JumpPass.scala: https://github.com/joernio/joern/blob/master/joern-cli/frontends/ghidra2cpg/src/main/scala/io/joern/ghidra2cpg/passes/JumpPass.scala[23] OssDataFlow.scala: https://github.com/joernio/joern/blob/master/dataflowengineoss/src/main/scala/io/joern/dataflowengineoss/layers/dataflows/OssDataFlow.scala[24] Node Type Steps - Reference Card: https://docs.joern.io/cpgql/reference-card/[25] queries.joern.io: https://queries.joern.io/[26] joernio/joern: https://github.com/joernio/joern[27] joernio/flatgraph: https://github.com/joernio/flatgraph[28] overflowdb: https://github.com/ShiftLeftSecurity/overflowdb[29] joern-vs-ocular: https://docs.shiftleft.io/joern/joern-vs-ocular[30] Joern Website: https://joern.io/[31] Joern Blog: https://joern.io/blog/[32] Node-Type Steps: https://docs.joern.io/cpgql/reference-card/[33] ShiftLeftSecurity/codepropertygraph - CPG 标准、查询语言以及相关工具: https://github.com/ShiftLeftSecurity/codepropertygraph[34] ShiftLeftSecurity/overflowdb - 内存图数据库实现: https://github.com/ShiftLeftSecurity/overflowdb[35] joernio/flatgraph - 新版内存数据库 (overflowdb-v2): https://github.com/joernio/flatgraph[36] docs.joern.io: https://github.com/joernio/website  
  
  
  
