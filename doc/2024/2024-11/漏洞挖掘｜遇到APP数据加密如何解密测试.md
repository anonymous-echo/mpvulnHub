#  漏洞挖掘｜遇到APP数据加密如何解密测试   
 黑白之道   2024-11-30 00:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
原文首发在：Freebuf社区  
‍  
‍  
  
https://www.freebuf.com/articles/mobile/413935.html****  
  
**文章中涉及的漏洞均已修复，敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！**  
## 0x01 加解密的意义  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsM4aE3oEeAe3NyhSksA6IRxiaN5wZ5lu2W26KcXRLgjpvJ3AdlDvkwUug/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
相信大部分测试过app的好兄弟都被这个问题困扰过，app数据包部分字段被加密，又或者是整个数据包被加密，这种大部分是json的数据你不解开根本就没法测试。于是乎本教程就出来了，本篇主要针对ios-app做一个初步的解析。  
  
首先如图所示，类似这样的大概率是aes加密  
> AAAAA+AAAAA/AAA=  
  
  
对初级加密还有不懂的朋友可以看我上篇文章，本文就不过多赘述了  
  
经验分享 | WEB渗透测试中遇到加密内容的数据包该如何测试 - FreeBuf网络安全行业门户  
## 0x02 先说解密实战与结果  
  
一次项目中遇到的  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMPHeCCbZ3DjmZtJ9c6rpkgAS4sM4rkpptpORGt7j4icEQVo9f6evq4Ig/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
密码字段加密  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsM4aE3oEeAe3NyhSksA6IRxiaN5wZ5lu2W26KcXRLgjpvJ3AdlDvkwUug/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
使用frida-trace -i “CCCrypt” hook ios成功拉取到了key与iv  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMW3zBoic14uVG8ayAO1o5lQQLEdTcqBLAUGXpYhJmtbaXEWJgJOQx18Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以看到也是成功的还原了加解密数据  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMhcFgUHqS1N2xHqPnrQK15SziaRyqL0SbhdJQGjM12pApMib24cR3gsrA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMvvTiaQVrR6CnaTuGvTica1WgqFw5MZjVyXaNBoFwlHteG4LcTFZZOaLw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 0x03 基础概念与准备  
  
首先你需要有一个越狱的苹果手机+你准备测试的app  
  
在pc端与苹果端部署好frida环境，可参考网上写好的文章  
  
【iOS安全】越狱iOS安装Frida | Frida使用 | 修改Frida-trace源码_ios frida-CSDN博客  
> frida-trace -UF -i “CCCrypt”  
  
  
然后这条命令是在你开启app时候使用的 意思是  
  
frida-trace = 你的frida工具  
  
-UF = 指定当前打开正在运行的app  
  
-i = 选择模式  
  
“CCCrypt” = 这是一个苹果默认的加密框架，你可以看到很多加密都是从这个框架里走的，因为苹果app商店审核机制非常的严格，你用一些自研的加密方式可能会上不了商店，这就是你为啥要钩这个的原因。  
  
frida和burp抓包其实差不多也是在特定时间点触发特定事件的时候去捕获数据，这个CCCrypt就是执行加解密操作的时候，应该很好理解。  
  
感兴趣的可移步  
  
CCCrypt函数——iOS加解密必知-CSDN博客  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMAzRdv8ibFia6k2fx1gibRs3cyZUtMKSS237RreMMBcrLpK7Jib7gHCT7HQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在你执行完成这一步的时候本地会生成钩取该函数的脚本，打开并修改成如下提供的脚本  
```
{
  /**
   * Called synchronously when about to call CCCrypt.
   *
   * @this {object} - Object allowing you to store state for use in onLeave.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Function arguments represented as an array of NativePointer objects.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onEnter(log, args, state) {
    log('CCCrypt() → 操作类型→', args[0]);
    log('CCCrypt() → 算法类型→', args[1]);
    log('CCCrypt() → 填充模式→', args[2]);
    log('CCCrypt() → 算法密钥→', hexdump(args[3]));
    log('CCCrypt() → 密钥长度→', args[4]);
    log('CCCrypt() → 算法 IV→', hexdump(args[5]));
    log('CCCrypt() → 加密/解密内容→', hexdump(args[6]));
    log('CCCrypt() → 加密/解密结果→', hexdump(args[8]));
  },

  /**
   * Called synchronously when about to return from CCCrypt.
   *
   * See onEnter for details.
   *
   * @this {object} - Object allowing you to access state stored in onEnter.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {NativePointer} retval - Return value represented as a NativePointer object.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onLeave(log, retval, state) {
  }
}
```  
  
这个是为了方便回显我们查看。  
## 0x04 数据包的定义  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMW3zBoic14uVG8ayAO1o5lQQLEdTcqBLAUGXpYhJmtbaXEWJgJOQx18Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
此处hook到了密钥和iv  
  
从算法类型判断0x0为aes128 加密算法  
  
以下是参考  
```
0x0 aes128
0x1 des
0x2 3des
0x3 cast
0x4 rc4
0x5 rc2
```  
  
填充模式的参考如下  
```
0x1 是pkcs7padding
0x2 是ecb 密钥
```  
  
因为aes128他密钥是16字节  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMKQ4HM9gLTjG4ibyGjsquRmCacahBzHNpnAeeIpcwHwW95O4vCC5Mkbg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
iv也是16字节  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsMJEwYFt5CZkQhUVt9libpZlVZvctj8sNnLh2iaubqY1icJxqRxhAbMnnKA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
所以我们这里得到他的密钥和iv  
  
密钥：30313032303330343035303630373038  
  
iv：30313032303330343035303630373038  
  
然后就可以愉快的加解密去继续渗透了  
## 0x05 总结  
  
此处的最难点在于，你得买个苹果手机hhh。  
  
本文用到的加解密网站推荐  
  
加密：http://tool.chacuo.net/cryptaes  
  
解密：https://www.ddosi.org/code/#recipe=Generate_all_hashes('All',true)  
  
因为aes会有不同的填充类型 有时候会踩坑  
  
也可以用utools的加解密 也是用起来很顺手  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTo4C96dBM8uLUyjObZf4NsM4VmZhvPZDB0LocibsqmYmsIm7XjKCYL9G6f4I4eVy8pdV9hOHhwtHow/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
