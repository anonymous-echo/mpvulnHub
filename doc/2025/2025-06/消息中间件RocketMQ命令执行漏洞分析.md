#  消息中间件RocketMQ命令执行漏洞分析   
NEURON  SAINTSEC   2025-06-05 11:15  
  
RocketMQ是由阿里捐赠给Apache的一款低延迟、高并发、高可用、高可靠的分布式消息中间件。RocketMQ既可为分布式应用系统提供异步解耦和削峰填谷的能力，同时也具备互联网应用所需的海量消息堆积、高吞吐、可靠重试等特性。  
  
  
  
**0‍**  
  
  
  
**1‍**  
  
  
**漏洞分析‍‍‍‍‍**  
  
  
  
RocketMQ 5.1.0及以下版本，RocketMQ的NameServer、Broker、Controller等多个组件外网泄露，缺乏权限验证，攻击者可以利用该漏洞利用更新配置功能以RocketMQ运行的系统用户身份执行命令。 此外，攻击者可以通过伪造 RocketMQ 协议内容来达到同样的效果。  
  
漏洞点位于FilterServer，比对一下版本差异，既然是命令执行尝试搜索Runtime，能够找到：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKRwxfPxxnTSqnpyIhxhht5N0zkx3IVbkCzCwHxNticUGgWZBXXgLu4kroIbSJNSQzsTibF3VF7NRw/640?wx_fmt=png "")  
  
callShell函数如果参数完全可控那么确实是一处命令执行的点，本地部署一下环境，若是要启动的话起一下Namesrv和Broker就可以了，需要设置一下ROCKETMQ_HOME为项目地址以及-n 127.0.0.1:9876指定一下namesrv的地址。  
  
在org.apache.rocketmq.broker.filtersrv.FilterServerManager#createFilterServer处调用了FilterServerUtil.callShell：  
```
```  
  
cmd取决于buildStartCommand函数：  
```
```  
  
例如我用-n参数指定namesrv地址，那么此处最后的cmd值为：  
```
```  
  
若指定了-c参数则为：  
```
```  
  
那么实际上可控点有三处，此命令简化后为:  
```
```  
  
同时查阅资料或者自己debug时都不难发现， BrokerController启动会创建一个定时任务每30秒去向NameSrv注册信息（broker的一个重要作用就是向namesrv注册路由信息，同时也会注册Broker自身信息）。  
  
org.apache.rocketmq.broker.BrokerController#startBasicService:  
```
```  
  
broker的每一个模块都会调用到，此时自然而然会调用到filter srv，进一步调用buildStartCommand进入到命令执行的函数，也就是说如果能够在运行环境中改动某一处可控点的值即可完成命令执行。  
  
  
**0‍**  
  
  
  
**2‍**  
  
  
**漏洞利用‍‍‍‍‍**  
  
  
这个漏洞本质上还是一个命令注入，现在的问题是:  
  
```
```  
  
此处并非直接可控，须知在执行命令前它会以空白为间隔将命令分割为数组再传入exec中：  
```
```  
  
这里需要稍稍绕一下，因为诸如ping&ls这种都是会被当成一个语句，同时分割空白，没办法以常规的方式注入，通常情况下都会用以下两种方式来解决：  
- 利用${IFS}绕过空格  
  
- 在要执行的shell前插入sh -c $@ | sh . echo  
  
那么更新配置来插入shell的方式其实很简单，在rocketmq项目下有tools这个包，DefaultMQAdminExt其下是所有运维方法的汇总，自然也可以用来更新配置，当然了如果熟悉协议也可以伪造协议完成更新配置。  
```
```  
  
此时连接后发现并没有执行命令，在前面的分析中还漏了一个点：  
```
```  
  
此处还要判断i<more才会进入到callShell，其中this.brokerController.getBrokerConfig().getFilterServerNums()  
取到的值是0，解决起来也很简单，它这里也是从broker的配置中取出，因此直接修改filterServerNums为大于0的值即可。  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTKRwxfPxxnTSqnpyIhxhhtvuf4FQRKT5WLv0ViaACRcia5v3gV8sQHHuZrL2VcODtL3DbFIGvHtBtw/640?wx_fmt=png "")  
  
从这里也能够很明显的看出漏洞的利用很简单，只需要目标的端口开放，版本符合即可利用。  
  
需要注意的是，这个漏洞在打了一次之后会由于更改了配置文件，同时broker会定期更新，因此会定期执行命令，打完后需要再次覆盖为原来的配置。  
## 修复  
- 使端口不对外开放  
  
- 更新版本至5.1.1以上或者4.9.6以上  
  
**0‍**  
  
  
  
**3**  
  
  
**reference‍‍‍‍‍**  
  
  
## [1] cve-2023-33246  
  
https://lists.apache.org/thread/1s8j2c8kogthtpv3060yddk03zq0pxyphttps://lists.apache.org/thread/1s8j2c8kogthtpv3060yddk03zq0pxyp  
  
[2] vulhub/rocketmq/CVE-2023-33246  
  
https://github.com/vulhub/vulhub/tree/master/rocketmq/CVE-2023-33246  
  
  
  
         
‍  
  
‍  
  
