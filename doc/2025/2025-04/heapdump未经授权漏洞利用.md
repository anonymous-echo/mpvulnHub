#  heapdump未经授权漏洞利用   
原创 simeon的文章  小兵搞安全   2025-04-12 23:48  
  
    在实际渗透过程中碰到api泄露以及类似若以cms监控等，可以对heapdump文件进行导出，通过分析，可以获取一些敏感信息，通过利用泄露的敏感信息可以获取一些有用的资料，有的甚至可以直接获取服务器权限。本文对heapdump利用的方法进行总结和介绍。  
  
1.1HeapDump及HeapDump_tools 简介  
  
1.HeapDump简介  
  
HeapDump 是 Java 虚拟机（JVM）在某一时刻内存使用情况的快照，记录了 JVM 堆中所有对象的详细信息，包括对象信息（对象的类名、字段值、引用关系等）、类元数据（类加载器、类名、静态字段等）、垃圾回收根对象（线程栈、静态变量等可以直接被 JVM 访问的对象）及线程的调用栈和局部变量等信息。  
  
HeapDump主要用来诊断内存泄漏、排查内存溢出（OOM）及性能优化。  
  
2.headdump_tool简介  
  
**Heapdump_tool**  
 是一个 **开源的命令行工具**  
，专门用于分析 Java 的 **Heap Dump**  
（堆转储）文件。它基于 jhat（JDK 自带的堆分析工具）实现，简化对堆转储文件的敏感信息提取和内存问题诊断。  
https://github.com/wyzxxz/heapdump_tool  
### 1.1.2Heapdump_tool常见参数  
  
1. 工具启动  
  
java -jar heapdump_tool.jar [heapdump_file]  
  
参数说明：heapdump_file：待分析的堆转储文件路径（支持 .hprof、.gz 等格式）。  
  
2. 交互式查询命令  
  
进入工具界面后，可通过以下命令查询数据：  
<table><tbody><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">命令格式</span></span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">功能</span></span></p></td></tr><tr style="height: 70px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">password</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">搜索所有包含</span></span><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">password</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">的字符串（关键词查询）。</span></span></p></td></tr><tr style="height: 36px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">len=10</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">查找所有长度为 10 的字符串（如密码、Token）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">class=&#34;shiro&#34;</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">按类名模糊搜索（如</span></span><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">org.apache.shiro</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">相关类的实例）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">id=0x1a2b3c</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">通过对象 ID 查找具体对象信息（需已知目标对象的十六进制 ID）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">re=^[A-Z0-9]{10}$</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">使用正则表达式匹配字符串（如匹配特定格式的密钥）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">shirokey</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">直接提取 Shiro 框架的 Session ID 或加密密钥（针对 SpringBoot 应用）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">geturl</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">提取所有 URL 地址（如数据库连接字符串、API 端点）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">getfile</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">提取文件路径或文件名（如配置文件路径）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">getip</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">提取 IP 地址（如数据库 IP、服务器地址）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">all=true</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">显示所有查询结果（默认过滤非</span></span><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">key-value</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">格式的数据）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="128" width="128" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="font-size: 12px;"><span leaf="">exit</span></span></code></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 12px;"><span leaf="">退出工具。</span></span></p></td></tr></tbody></table>  
3. 高级参数（启动时指定）  
  
java -jar heapdump_tool.jar [heapdump_file]   
  
查询方式：  
  
1. 关键词       例如 password   
  
2. 字符长度     len=10    获取长度为10的所有key或者value值  
  
3. 按顺序获取   num=1-100 获取顺序1-100的字符  
  
4. class模糊搜索  class=xxx 获取class的instance数据信息  
  
5. id查询       id=0xaaaaa  获取id为0xaaaaa的class或者object数据信息  
  
4. re正则查询    re=xxx  自定义正则查询数据信息  
  
6.获取url,file,ip  
  
shirokey 获取shirokey的值  
  
geturl   获取所有字符串中的url  
  
getfile  获取所有字符串中的文件路径文件名  
  
getip    获取所有字符串中的ip  
### 1.1.3漏洞挖掘  
  
利用未授权访问的接口（如 Spring Boot Actuator 的 /actuator/heapdump 端点）下载 Heap Dump 文件，在若以监控系统以及一些api系统中可以直接获取/actuator/heapdump文件。  
  
1.Spring Boot 1.x 版本及Spring Boot 2.x 版本常见端点及功能  
  
（1）Spring Boot 1.x 版本  
  
在 Spring Boot 1.x 中，Actuator 的端点路径是直接从根路径 /  
 开始的，例如 /health  
、/env  
、/metrics  
 等。****  
<table><tbody><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">端点</span></span></strong></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">功能</span></span></strong></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/configprops</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示所有</span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">@ConfigurationProperties</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">注解的配置类及其绑定的值。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/env</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示 Spring 的</span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">ConfigurableEnvironment</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">（环境变量和配置属性）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/health</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示应用程序的健康状态（如数据库连接、磁盘空间等）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/httptrace</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示最近的 HTTP 请求跟踪信息（如请求方法、响应状态码）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/metrics</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示当前应用程序的监控指标（如内存使用、线程数、HTTP 请求计数等）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/mappings</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示所有</span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">@RequestMapping</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">路径的整理列表（包括控制器和处理方法）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/threaddump</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示 JVM 的线程堆栈信息。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/heapdump</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">下载整个 JVM 的堆转储文件（用于分析内存问题）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="165" width="165" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/jolokia</span></span></code></p></td><td data-colwidth="519" width="519" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">提供 JMX-HTTP 桥接功能，允许通过 HTTP 访问 JMX Beans。</span></span></p></td></tr></tbody></table>  
（2）Spring Boot 2.x 版本  
  
在 Spring Boot 2.x 中，Actuator 的端点路径统一以 /actuator 为前缀，例如 /actuator/health、/actuator/env 等。这种设计更符合 RESTful 风格，并且便于区分 Actuator 端点与其他应用路径。  
<table><tbody><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">端点</span></span></strong></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">功能</span></span></strong></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/configprops</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示所有</span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">@ConfigurationProperties</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">注解的配置类及其绑定的值。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/env</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示 Spring 的</span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">ConfigurableEnvironment</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">（环境变量和配置属性）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/health</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示应用程序的健康状态（如数据库连接、磁盘空间等）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/httptrace</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示最近的 HTTP 请求跟踪信息（如请求方法、响应状态码）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/metrics</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示当前应用程序的监控指标（如内存使用、线程数、HTTP 请求计数等）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/mappings</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示所有</span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">@RequestMapping</span></span></code></p><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf=""> </span></span><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">路径的整理列表（包括控制器和处理方法）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/threaddump</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">显示 JVM 的线程堆栈信息。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/heapdump</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">下载整个 JVM 的堆转储文件（用于分析内存问题）。</span></span></p></td></tr><tr style="height: 33px;"><td data-colwidth="207" width="207" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><code style="font-family: SFMono-Regular, Consolas, Liberation Mono, Menlo, Courier, monospace;background-color: rgba(0, 0, 0, 0.06);border: 1px solid rgba(0, 0, 0, 0.08);border-radius: 2px;padding: 0px 2px;"><span style="color: rgb(44, 44, 54);font-size: 14px;"><span leaf="">/actuator/jolokia</span></span></code></p></td><td data-colwidth="612" width="612" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="color: rgb(44, 44, 54);font-size: 16px;"><span leaf="">提供 JMX-HTTP 桥接功能，允许通过 HTTP 访问 JMX Beans。</span></span></p></td></tr></tbody></table>  
2.直接访问api接口测试  
  
例如访问https://**.api.***.com/api/actuator/heapdump，如图2-1所示，直接下载该文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvS8XpOSC7nvPcbTZficicfB7dyjAgHLAoZFsWTS7GnkLsWgt6WWWx0217A/640?wx_fmt=png&from=appmsg "")  
  
  
图1 直接下载heapdump文件  
  
3.敏感信息获取  
  
（1）1.x获取  
  
/configprops  
  
/env  
  
/health  
  
/httptrace  
  
/metrics  
  
/mappings  
  
/threaddump  
  
/heapdump  
  
/jolokia  
  
（2）2.x版本获取  
  
/actuator/configprops  
  
/actuator/env  
  
/actuator/health  
  
/actuator/httptrace  
  
/actuator/metrics  
  
/actuator/mappings  
  
/actuator/threaddump  
  
/actuator/heapdump  
  
/actuator/jolokia  
  
如图2-2所示，泄露信息中包含密码等信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvSdsqtDX8YK6OMIepg2oaZfpGPibT1Uy98w66A1dPBSj2Idbpc4z1uDibA/640?wx_fmt=png&from=appmsg "")  
  
图2-2 泄露信息查看  
### 1.1.4实际利用案例  
  
1.下载heapdump文件分析  
  
将  
heapdump_tool.jar及heapdump放在同一个目录，jdk为java8版本。执行命令：  
  
java -jar heapdump_tool.jar heapdump  
  
可以选择0和1两种模式，1是搜索全部数据，相对时间会长一些，如图2-3所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvSsyhmyLqbK2ibANho69LekJWPDbTUNP8aLyqiaXyst3zvbF1vxSI1qdcA/640?wx_fmt=png&from=appmsg "")  
  
图2-3 搜索所有的信息  
  
（1）搜索密码  
  
当全部信息搜索完毕后，可以执行搜索关键字进行搜索，例如password，  
heapdump_tool会将包含password关键字的信息全部列出来，如图2-4所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvSlJ6gQFmV2m9QBP6NZjPJ64QZ5RWy15PmV4DfeAicdBP1mnJ8eR6xkaA/640?wx_fmt=png&from=appmsg "")  
  
 获取密码：Yuanch@anGb0lUo#0Aa  
  
（2）搜索oss AccessKey及SecretKey  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvSCZOcaNZJxEY2G5micuMFwEdMvpiaxqWsZMofe9w0HnWrjcXpibshfdlnA/640?wx_fmt=png&from=appmsg "")  
  
3.获取ip地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvSWGEhVghnT1sQKe8ePINdyVibnlNaPnVSJjicbXTNxw2hFYfAEJLibS3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
4.获取url地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHq3bAh4oburGiaMKMyr2nvS39KNKh7zhzBLvFQChqibwhUibDa7wwRJ4DUtBbK3Q4enKz3hMGVNQzBA/640?wx_fmt=png&from=appmsg "")  
  
  
令总结  
  
java -jar heapdump_tool.jar heapdump1  
  
AccessKey、SecretKey  
  
password  
  
geturl  
  
getip  
  
getfile  
  
  
