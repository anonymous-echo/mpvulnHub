#  不同视角学习Java代码审计之文件读取漏洞   
 闪石星曜CyberSecurity   2025-05-29 08:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRovPmpEqR4Yun5z3u3dumOa5wmdibU9beZASvo8x3YRYIMVgpcPrHTkrg/640?wx_fmt=gif&from=appmsg "")  
  
声明：文章涉及网络安全技术仅作为学习，从事非法活动与作者无关！  
  
本篇为代码审计系列任意文件读取基础理论篇第三篇，看完本篇你将掌握关于文件读取漏洞的代码视角原理剖析、基础挖掘漏洞核心能力，看完如有技术错误欢迎评论区指正。  
- 漏洞原理  
  
- 业务视角DEMO代码  
  
- 漏洞校验DEMO代码  
  
- 代码层面防护思路  
  
- 实战审计案例  
  
  
  
  
**任意文件读取**  
  
  
一  
  
漏洞原理  
  
1.1业务原理视⻆  
  
用户使用电脑浏览器操作企业Web站点某些功能的背后逻辑业务逻辑是在文件读取功能，例如：读取业务模版文件等。企业用户使用的是正常的文件读取，恶意用户读读取任意恶意文件会导致敏感文件泄漏，利用敏感信息进行下一步攻击活动。  
  
  
1.2漏洞原理视⻆  
  
任意文件读取漏洞其技战术是  
初始访问 | QT1190.016 文件读取  
，主要是在文件读取代码逻辑过程中未对读取文件路径与文件名称进行校验，导致敏感类型文件读取造成信息泄露  
  
二  
  
业务视⻆DEMO代码  
  
常见文件上传内置方法有BufferedReader读取或HttpServletResponse.getOutputStream()，文件读取上传功能流程如下：  
- 获取文件类型  
  
- 读取文件流  
  
- 文件流写入  
  
- 设置响应头  
  
  
  
2.1BufferedReader 方式文件读取  
  
BufferedReader 是 java.io或java.nio包内置函数提供了基于流的文件读取方式  
  
File file = new File("/path/to/file.txt");  
  
if (file.exists() && file.isFile()) {      
  
try(  
BufferedReaderreader=newBufferedReader(newFileReader(file)  
)) {String line;  
  
while ((line = reader.readLine()) != null)  
  
{System.out.println(line);}}   
  
catch (IOException e)   
  
{e.printStackTrace();}}  
  
2.2HttpServletResponse.getOutputStream()和getWriter()方式文件读取  
  
  在 Java Web 项目中，通常需要结合Servlet和HttpServletResponse来读取文件并返回给客户端   
  
@WebServlet("/readFile")  
  
publicclassFileReadServletextendsHttpServlet{@OverrideprotectedvoiddoGet(HttpServletRequestreq,HttpServletResponseresp) throws IOException {  
  
Path path = Paths.get("/path/to/file.txt");  
  
if(Files.exists(path)&&Files.isRegularFile(path)){resp.setContentType("text/plain");  
  
try(  
  
BufferedReaderreader=Files.newBufferedReader(path);                
  
PrintWriter writer = resp.getWriter()) {  
  
String line;  
  
while ((line = reader.readLine()) != null) {writer.println(line);}}}  
  
else {resp.setStatus(HttpServletResponse.SC_NOT_FOUND);            resp.getWriter().println("File not found");      }  
  
}  
  
}  
  
  
三  
  
 漏洞校验DEMO代码  
  
针对业务代码多种方式做读取/下载操作，主要是针对java中文件操作类进行关键词"搜索"。  
  
文件读取漏洞限制：  
- 文件名称限制：限制允许下载的文件类型，例如只允许下载`.pdf`、`.txt`、`.jpg`等安全文件。  
  
- 文件路径限制：限制根路径、目录穿越字符、防止路径直接拼接  
  
  
  
3.1文件类型限制  
  
**3.1.1 获取文件文件后缀名：注意获取****位置**  
     StringSuffix=fileName.substring(fileName.lastIndexOf("."));  
  
**3.1.2 文件后缀名白名单内容：**  
  
String[] SuffixList = {".jpg", ".png", ".jpeg", ".gif"};  
  
3.2文件路径限制  
  
- 使用规范化函数（如`getCanonicalPath()``Paths.normalize()`  
  
）解析文件路径，返回文件的规范化路径，过滤路径中的`.`和`..`，确保路径在预期范围内  
  
- 使用白名单机制限制文件路径的根目录  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoOqPOSAYIibYEYyQXxXZLLvICeltCxsYVB6Is4UssX0kkOzkA4op3Hibw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoEmRZ1ibmqRyMibsI0OoxrPIJVCR79xJUYGpicegOwkpF3F0fGrk7UibE1Q/640?wx_fmt=png&from=appmsg "")  
  
  
四  
  
  实战审计案例  
  
之前两篇SQL注入、文件上传均为白盒审计，此篇文件读取/下载为黑盒审计，以JFinalCMS项目部署后从系统功能开始为入口定位项目代码视角进行讲解。文件下载/读取敏感文件漏洞利用存在两个前提条件，代码审计目标也是如此。利用条件如下：  
  
- 文件路径可控  
  
- 文件名称可控  
  
4.1JFinalCMS文件读取分析  
  
**4.1.1项目部署**  
  
 maven更新Pom.xml中依赖项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRouV8CJYibV02EmuNKQvqPrYUicZ3r2jax7vH9NHicO2jeibMY7y9pLNvRUQ/640?wx_fmt=png&from=appmsg "")  
  
  
**4.1.2mysql数据库创建**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRo0Nia4MAT6bfXQDCEdLWPKcU6R9F9jmIIbwRc1st5I2auiauWGuCNIvmw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoRcHfNNLbcdY4hkFsmn5Tx4sFywhPAuhCxpic4kPDmwHlp4ibFoUo54pw/640?wx_fmt=png&from=appmsg "")  
  
  
**4.1.3Tomcat部署启动项目**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRotK5lkcLsZs7iaF88WXzTCwjEB0kAMGJnGWhZib9hKqxEiaMQofuE7xTqA/640?wx_fmt=png&from=appmsg "")  
  
  
**4.1.4文件读取/下载功能定位**  
-  管理后台-系统管理-模版管理  
  
通常模版管理中存在模版上传、模版编辑、模版下载等功能，其中编辑的代码逻辑通常都是文件读取后再展示在视图层  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoibu6RxHiakIWxCGicFqEG20icjibc0iaMek6icSz30Fkn1UicnhIsSqNx8fODg/640?wx_fmt=png&from=appmsg "")  
  
- 读取文件类型/路径校验逻辑  
  
查看about.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoKySlwicQP2ahyiaRGGfcomrYRNicsUlW08KVnh21aRiaVMQ0YmDk6ZgNEg/640?wx_fmt=png&from=appmsg "")  
  
  
- 查看BurpSuite对应包接口定位/admin/template/edit?  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRogozGCXGkMHhXMJ9LLNnFFNl2QwccGIzibhibI5YC4TAsTefhfX37lgQQ/640?wx_fmt=png&from=appmsg "")  
  
  
Idea关键词查找"edit"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoaafDCYIRlKcOjKwgLeVhLkBjC1vEj6v69znIyWH3v5k2LgCV173jIw/640?wx_fmt=png&from=appmsg "")  
  
**4.1.5静态功能逻辑审计**  
  
TemplateController.java 中的 edit() 方法用于处理模板文件的编辑请求。它从请求参数中获取文件名和目录信息，构造出模板文件的路径，并读取文件内容，将这些信息传递给前端页面以供编辑。  
- 获取请求中的 fileName 和 directory 参数。  
  
- 如果 fileName 为空，则返回错误页面。  
  
- 设置 directory 和 fileName 到视图属性中，供前端使用。  
  
- 构建模板文件的实际路径 filePath。  
  
- 使用 TemplateUtils.read(filePath) 读取模板文件内容:TemplateUtils.read(filePath)->readFileToString(templateFile, "UTF-8")->openInputStream(file)  
  
- StringEscapeUtils.escapeHtml() 对内容进行 HTML 转义后设置到视图属性中。调用Entities.HTML40.escape()用于防止XSS  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRo652KLc4OPJyoYXSVcfSibNGqIOLVQibNKFPXWsg14DpN2WU2Uibic88HXQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoBiaJ2Gtpv1damibgqcGq9ECvBLApHZm7QIKBSTYLV3EkRPneGMwHDYMQ/640?wx_fmt=png&from=appmsg "")  
  
最后渲染 template/edit 页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoh8cRAPmZpMDOonB3De0Lhf5uia3fibrVt4TiaeZysnjlUveANVAopY4ng/640?wx_fmt=png&from=appmsg "")  
  
**4.1.4动态发包测试**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoMfuiaQwzEC0mWL2moDCXUMVZb0cicQwASSISIttM5f1tOiatibWlvcp2Ag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoEhuaMH3gFZK3kR4HBAzjiaaRIYflVluGnKfRicHJzREOhriaprDg8accQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8wLNfl9yoSbtTkE0giapzrRoJvcBBLIMk1UyQJafzajAoYeV2RwB496bvhkUxPibTRUFDApQ359WgjA/640?wx_fmt=png&from=appmsg "")  
  
END  
  
  
  
  
  
  
