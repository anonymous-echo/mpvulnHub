#  代码审计｜NginxWebUI多处漏洞   
 白帽子社区团队   2024-07-26 22:50  
  
本文仅用于技术研究学习，请遵守相关法律，禁止使用本文所提及的相关技术开展非法攻击行为，由于传播、利用本文所提供的信息而造成任何不良后果及损失，与本账号及作者无关。  
  
**关于无问社区**  
  
  
无问社区致力于打造一个面向于网络安全从业人员的技术综合服务社区，可**免费**获取安全技术资料，社区内技术资料知识面覆盖全面，功能丰富。  
  
  
特色功能：划词解析、调取同类技术资料、基于推荐算法，为每一位用户量身定制专属技术资料。  
  
无问社区-官网：http://wwlib.cn  
## 0x01 前言  
  
目标信息，源码名称:nginxWebUI，下载地址:https://www.nginxwebui.cn/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNiaSJwGjI9wHKbGdzsyj2b6BGKfmzWliciayWAUxEfKFcUYPN8od8HAShQ/640?wx_fmt=png "")  
  
因为下载下来的是jar包，所以我们通过反编译来拿到源码。  
```
官方说明:https://www.nginxwebui.cn/product.html

windows启动如下：
java -jar -Dfile.encoding=UTF-8 D:/home/nginxWebUI/nginxWebUI.jar --server.port=8080 --project.home=D:/home/nginxWebUI/

```  
## 0x02 获取源码  
  
这里推荐的两个反编译工具  
- 1.luyten  
  
- 2.jd-gui  
  
这里我使用的 **jd-gui** 这两款软件 在github 均可以搜到下载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN4VtFG24BIO8s2ial0usbwlIFywXCBOlAKEMDQ1AsIyeseKLa3hDu6aA/640?wx_fmt=png "")  
  
选择 "Save All sources" 导出该项目，导出成功后 使用IDEA去打开该项目  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNZpcM4A1AXW7R720vp0dicvw3MsvZfsIiaIfcyjlCzE4HO80nfo1SJQbA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNKUjYrT1W1eXgIGuoicshibQRfBelDuBYs19Udd886mAYQB8odAY4Uz2Q/640?wx_fmt=png "")  
  
我们在这里开始远程JVM调试，一般我们java web远程debug的话  只要设置好三要素  
- 1.主机  
  
- 2.端口  
  
- 3.JDK版本  
  
如图  服务端的地址为192.168.238.132  端口为8089 复制给出的命令行实参  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNuibxXStmXpMuAlWj6zU6flOszOutNhkCicuKkaNEor04QpL1HzWebHdA/640?wx_fmt=png "")  
```
添加到启动jar包的cmd命令:
java  -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8089 -jar -Dfile.encoding=UTF-8 D:/home/nginxWebUI/nginxWebUI.jar --server.port=8081 --project.home=D:/home/nginxWebUI/ 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNEJHGWSWTKDcuDwIGsZjZQlVVSzOKVkiaWZL9PWop8UEic3CzzQhUUVbQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNWFugCgA4pPqCoh4zxeSLfP24ic5iaPuicAZONOjgp1QnWiaTSDx7r4cRPQ/640?wx_fmt=png "")  
## 0x03 审计结果  
#### 1. 登录无视验证码爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNVz9gv6RZFq3nichictnKfhrkRTMZaGlH0ByypoGooPOIX3micexFzQBZg/640?wx_fmt=png "")  
  
首先去对应路由关系 清楚运行的逻辑 就能快速去挖掘了，这里登录抓包 url 为 /adminPage/login/getAuth 相当于为 **contoller/adminpage/Logincontoller/** 方法直接找Mapping绑定  
  
这样对应上了就知道是怎么传参 就能找到对应源码进行审计  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNrVmMCtNzdBdm32ZnxVzKsEUxcOHVVJ3bQVSMjTXrHuetEHJiahWfIGQ/640?wx_fmt=png "")  
  
这边形参 用户可以直接传参 如下不为null 就可以绕过验证码生成验证的这个流程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNIgzWDvxJTTJJicJ41wnPE25M2AXGgusEqhNmSLVmsOLDAGbUAPIzOoA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNCWMJ30hSSSl3xchpAH8Al9MYziaxgqzIK8JMHldqmJ3GGbKPdxkaFNw/640?wx_fmt=png "")  
  
爆破name 和pass的话只要经过两次base64解码就可以  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNVTuvabicJuosBjgCAW6NyIHhRYvz6w6xCMPwKzdeBvFvN4w9DVAG1YQ/640?wx_fmt=png "")  
#### 2. 权限绕过  
  
config下目录AppFillter 类发现doFilter方法，通过全局过滤器发现这里校验不严格,可以大小写绕过。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNYNrzbU7rQeGhibMgFjdOiazZnU7qIvvhVj7yibUgJ83xAeOQyQnUBmhRw/640?wx_fmt=png "")  
  
只要是，只通过全局过滤器鉴权的路由的都可以进行未授权操作  
#### 3. 任意文件上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNibvK6uwmjKibiaj31kwwaiaJGaZ8MbN19ib4j9USN9aKQic2zqFQYWv45ccg/640?wx_fmt=png "")  
  
通过全局搜索upload 找上传点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNfQcIFFtBdBNJSrbgiaiafYKOWJIUc5SICb0ft2ow1ukny1S7hU6mD8Mw/640?wx_fmt=png "")  
  
上传参数为file，这里直接是原生文件名。上传到了/tmp目录，不过文件名可控可以跨目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN9aD9vC0mFkw0wpRpTb5kMpMySk2icfU4v1Zp32raKaFjSm961dmgLAA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN7XBQoNxVZSRTnLM25M3aag9P12ibx5XKoVOsV7mdkvgwt1Ef1ukRaCw/640?wx_fmt=png "")  
  
所以我们只需要网站的绝对路径就可以getshell。不知道他获取文件绝对路径用的哪个函数，直接正常登录系统看了一遍功能点，发现在conf这个类里打印了网站的绝对路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN9ma8g3Msw897WiarCc70ko7ARNUhUG44pEDCCzlX9vsuUSJjEbynWYQ/640?wx_fmt=png "")  
  
直接定位到该源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN4JOrBUyZWsfYTnavypzWPR14OzHXmPVd6r5g23DqBqTBlqicQNxS9lQ/640?wx_fmt=png "")  
  
不过，突然想起是jar包启动的。如果是类似tomcat的这种就能Getshell了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNsnw5ibjmXAIybdIehK8RLNAmq6pibBIQe80Gq9zBYkmXb7yhXE9rIa3g/640?wx_fmt=png "")  
#### 4. RCE - 执行恶意jar包(1)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN9BMoybtPt4UIXtqqSqhmm8227RBNo4h5UZOMCbzsAmwhchlzXsmJjA/640?wx_fmt=png "")  
```
 @Mapping("/adminPage/main/autoUpdate")
 public JsonResult autoUpdate(String url) {
//  if (!SystemTool.isLinux()) {
//   return renderError(m.get("commonStr.updateTips"));
//  }

  File jar = JarUtil.getCurrentFile();
  String path = jar.getParent() + "/nginxWebUI.jar.update";
  LOG.info("download:" + path);
  HttpUtil.downloadFile(url, path);
  updateUtils.run(path);
  return renderSuccess();
 }

```  
  
获取jar包的绝对路径，然后远程下载回来。然后进入一个run方法，跟进run方法查看。  
```
 public void run(String path) {
  ThreadUtil.safeSleep(2000);

  String newPath = path.replace(".update", "");//
  FileUtil.rename(new File(path), newPath, true);//将下载到的文件去除后缀.update

  String param = " --server.port=" + port + " --project.home=" + home;

  if ("mysql".equals(type.toLowerCase())) {
   param += " --spring.database.type=" + type //
     + " --spring.datasource.url=" + url //
     + " --spring.datasource.username=" + username //
     + " --spring.datasource.password=" + password;
  }

  String cmd = null;
  if (SystemTool.isWindows()) {
   cmd = "java -jar -Dfile.encoding=UTF-8 " + newPath + param;
  } else {
   cmd = "nohup java -jar -Dfile.encoding=UTF-8 " + newPath + param + " > /dev/null &";
  }

  LOG.info(cmd);
  RuntimeUtil.exec(cmd);

```  
  
**RuntimeUtil.exec(cmd);** 最后一行执行命令，回溯到cmd命令，是 **java -jar    newpath** 是我们可控的，也就是说我们能控制他运行的jar文件，所以我们在自己的服务上放一个恶意jar包让他来下载并且执行。  
#### 5. RCE - 2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNKVgbRXBLFDThMH8WWgv9fC9eYaHTEe4vDKdhq8gnibf1gzDWwXfxPaw/640?wx_fmt=png "")  
  
**confController.runCmd** 这里他调用了conf控制器类的**runCmd方法** 跟进去看，这里调用了exec方法，可以直接RCE。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNUT3xvqN9KjDw1wCIg2kKNaUGk9AVGYkXtqJ4N8wrjoOGekAIgx6Ricw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNICDFmB8D6KHkdLgMAP1UOHTPOxWAMOXydXyHGbd2vF4uqGmnyS0viaw/640?wx_fmt=png "")  
#### 6. RCE - 3  
  
以此之外，我们还可以去寻找其他调用这个runCmd方法的类，挖掘出更多的RCE  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZN7A4lGrozQBRkOdiaDQ8WCj80JyhYp4vgibQ3Nu2Wso3icb4BwROo8ic01w/640?wx_fmt=png "")  
```
public JsonResult cmdOver(String[] remoteId, String cmd, Integer interval) {
  if (remoteId == null || remoteId.length == 0) {
   return renderSuccess(m.get("remoteStr.noSelect"));  // 需要对remoteId进行传参
  }

  StringBuilder rs = new StringBuilder();
  for (String id : remoteId) {              
   JsonResult jsonResult = null;
   if (id.equals("local")) {   //remoteId 进入流程
    if (cmd.contentEquals("check")) {
     jsonResult = confController.checkBase();
    }
    if (cmd.contentEquals("reload")) {
     jsonResult = confController.reload(null, null, null);
    }
    if (cmd.contentEquals("replace")) {
     jsonResult = confController.replace(confController.getReplaceJson(), null);
    }
    if (cmd.startsWith("start") || cmd.startsWith("stop")) {   //cmd值开头为start 进入RCE
     jsonResult = confController.runCmd(cmd.replace("start ", "").replace("stop ", ""), null); //会自动将start 替换为空  
    }

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNvpqbCsPYMHxrlqjwa9ns7zLSGV9E1HCbw5qibYgeUDtV8hpuGlbTbyw/640?wx_fmt=png "")  
#### 7. 任意文件读取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfhINTSDBzOAcwkQ1rFSEdZNmEL2NiaEz0Is2CvNhjIIKeWlicgbc52hXcldqtNmRlo713PG21HibjubA/640?wx_fmt=png "")  
## 0x04 结尾  
  
承接红蓝对抗、安全众测、安全培训、CTF代打、CTF培训、PHP / JAVA / GO / Python 代码审计、渗透测试、应急响应 等等的安全项目，请联系下方微信。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfgp6OTRAV6boicrQdeFONewFSSYzuC8LYsM9hOrv3K6qVeUCUgoEZmfReVGJIjL6o9BE6MZAGEO87g/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
