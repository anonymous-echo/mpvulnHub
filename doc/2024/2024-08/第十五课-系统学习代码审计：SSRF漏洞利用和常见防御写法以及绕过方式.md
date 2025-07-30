#  第十五课-系统学习代码审计：SSRF漏洞利用和常见防御写法以及绕过方式   
开发小鸡娃  安全随心录   2024-08-21 22:31  
  
SSRF漏洞  
  
读完需要  
  
6  
分钟  
速读仅需 2 分钟  
  
视频教程：(   
https://www.bilibili.com/video/BV1KT421k7ZE )  
  
主要内容：  
  
1、Java 中发起网络请求的常见类  
  
2、不同类支持的不同协议  
  
3、防御手法  
  
4、绕过手法  
  
**/**SSRF**/**  
  
**1 定义**  
##      
  
SSRF 译为服务器端请求伪造，是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。并且 SSRF 攻击的目标是外网无法访问到的内部系统，同时请求都是又服务端发起的，所以服务端能够请求到与其自身相连接的与外网隔离的内部系统。类似于当作跳板进行攻击。  
  
**2 攻击流程**  
##      
> 攻击者与服务器构建请求。服务器向客户端发送构建的请求。客户端响应服务器发送的请求。服务器向攻击者返回客户端的请求。  
  
  
**3 危害**  
##      
> 可以对外网、服务器所在内网、本地进行端口扫描，获取一些服务的 banner 信息。攻击运行在内网或本地的应用程序（比如溢出）。对内网 web 应用进行指纹识别，通过访问默认文件实现。攻击内外网的 web 应用，主要是使用 get 参数就可以实现的攻击（比如 struts2，sqli 等）。利用 file 协议读取本地文件等。  
  
  
**4 利用**  
##      
  
**4.1 URL 关键字挖掘**  
###      
  
share、wap、url、link、src、source、target、u、display、sourceURl、imageURL、domain  
  
**5 伪协议**  
##      
```
file:/// 从文件系统中获取文件内容，如，file:///etc/passwd
dict:// 字典服务器协议，访问字典资源，如，dict:///ip:6739/info
sftp:// SSH文件传输协议或安全文件传输协议
gopher:// 分布式、文档传递服务，可使用gopherus生成payload
sftp:// SSH文件传输协议或安全文件传输协议
ldap:// 轻量级目录访问协议

tftp:// 简单文件传输协议
```  
  
  
**6 Java 中发起网络请求的常见类**  
##      
  
关键词：  
```
HttpURLConnection.getInputStream
URLConnection.getInputStream
Request.Get.execute
Request.Post.execute
URL.openStream
ImageIO.read
OkHttpClient.newCall.execute
HttpClients.execute
HttpClient.execute
BasicHttpEntityEnclosingRequest()
DefaultBHttpClientConnection()
BasicHttpRequest()

```  
  
  
**6.1 URLConnection**  
  
###      
> 包: java.net简介: URLConnection 是 Java 中所有代表应用程序与 URL 之间通信链接的抽象类。它是网络请求类的基类。支持的协议有：file 、 ftp 、 mailto 、 http 、 https 、 jar 、 netdoc 、 gopher  
  
  
```
public static void testURLConnect(){
    try {
        // 创建一个URL对象，指向需要访问的网页地址
        URL url = new URL("http://www.baidu.com");
        // 通过URL对象打开一个连接
        URLConnection connection = url.openConnection();
        // 实际执行连接操作
        connection.connect();

        // 获取连接后的输入流，用于读取网页内容
        InputStream inputStream = connection.getInputStream();
        // 使用BufferedReader读取输入流中的内容，这样可以按行读取
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        // 循环读取每一行，直到没有内容为止
        while ((line = reader.readLine()) != null) {
            // 输出读取的每一行内容
            System.out.println(line);
        }
        // 关闭BufferedReader以释放资源
        reader.close();
    } catch (Exception e) {
        // 捕获并处理所有异常
        e.printStackTrace();
    }

}

```  
  
  
**6.2 HttpURLConnection**  
  
###      
> 包: java.net简介: HttpURLConnection 是 URLConnection 的子类，专门用于处理 HTTP 协议。它提供了额外的功能，如设置请求方法（GET、POST 等）、获取响应代码等。支持 GET、POST、PUT、DELETE 等方式  
  
  
**6.3 HttpClient**  
###      
  
    Java 11 引入了 HttpClient 作为一个新的 API，用于在 Java 应用程序中进行 HTTP 通信。HttpClient 提供了发送 HTTP 请求和接收 HTTP 响应的功能，并且相比于依赖第三方库如 Apache HttpClient 或 OkHttp，它提供了一种简单、一致且更加集成的方式来处理 HTTP 通信。作为 Java 的一部分，HttpClient 被设计成与 Java 平台更好地集成，使得开发者能够更轻松地处理 HTTP 请求和响应，同时减少了对外部库的依赖。  
> 包: java.net.http简介: HttpClient 是在 Java 11 中引入的新的 HTTP 客户端 API，支持异步请求、WebSocket、HTTP/2 等现代功能。如果在使用 Java 11 之前的版本，并且想要使用类似的功能，你可能需要引入第三方库的依赖，如 Apache HttpClient。以下是使用 Apache HttpClient 的一个示例依赖项：  
  
  
```
<!-- Apache HttpClient依赖 -->
<dependency>
    <groupId>org.apache.httpcomponents</groupId>
    <artifactId>httpclient</artifactId>
    <version>4.5.13</version> 
</dependency>
```  
  
  
**7 防御代码写法**  
##      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9MnpyqibuMRYyz7DmhdkibbBpsw7F8tQiaUicQNIl08nUl70OYsXicDKHjVza4qia10fQ6F6wGZH5Zr6nbzA9qbWdy4A/640?wx_fmt=png&from=appmsg "")  
  
****  
****  
**8 绕过**  
##      
  
**8.1 dns 重绑定**  
https://xz.aliyun.com/t/7495?time__1311=n4%2BxnD0Dy7GQ3AKeD5DsA3rcC%3D%2FjO4boTD  
###      
  
****  
  
