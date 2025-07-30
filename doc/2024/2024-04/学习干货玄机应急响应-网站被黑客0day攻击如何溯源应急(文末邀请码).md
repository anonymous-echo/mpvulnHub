#  学习干货|玄机应急响应-网站被黑客0day攻击如何溯源应急(文末邀请码)   
 信安404   2024-04-24 13:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**0x01 前言**  
  
**环境提供：知攻善防实验室**  
```
https://mp.weixin.qq.com/s/5ibP6E8R-GPtOEJeFK8qZA
```  
  
环境背景：应急响应工程师小王收到安全设备警告，服务器设备被植入木马病毒，需进行上机排查  
  
**注：此处环境原作者未做攻击者具体步骤，原WP直接上帝视角给出的答案，对于初学者可能不太理解，以下我将按照我的思路去写，如果思路不对，烦请原作者改正**  
  
    **文末抽取邀请码、转发点赞等邀请好友增加中奖率，基本人人可得**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdDF4SEmKmJBiajSOibusWvib8ZynyrC88Z29DPaFicxDRawuvMA4IKHS6RA/640?wx_fmt=png&from=appmsg "")  
  
**关于邀请码只有三种方式可得：**  
```
1. 公众号进行抽奖活动获取(不定时)
2. 官方微信、Q群内不定时发放(拼手速)
3. 投稿应急响应相关镜像及WP(解题思路)
    可申请定制邀请码并送金币
```  
  
**相关规则查看如下文章：****关于玄机应急响应平台公开须知**  
  
**适用于安全运维、网络运维、安全服务及在校学生练习、赛前练习(环境嵌入了各地、各官方比赛的大部分应急响应镜像)、包括日常应急处置环境、个人灵活制作环境**  
  
*** 文章仅用于参考学习、禁止恶意利用传播非法行为**  
  
**0x02 题目详情**  
  
**此环境围绕西湖论剑PHPEMS复现，环境作者投稿没有说明，这是后面找到相关文章并进行的最新总结(非上帝视角)**  
```
https://mp.weixin.qq.com/s/P7akQHPp4saCl16E0Kw4tA
```  
```
1. 分析黑客的 IP 为多少,将黑客 IP 作为 FLAG 提交;
答: 192.168.20.1
```  
  
首先使用netstat查看本地端口开放情况，ps -ef看到是安装宝塔的****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdYCPicoDYKricWMUjXRgzBuRvoZ1EcGZSuxBKN6XeLg5vLBMhgLvtgiaQw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdy1xibgoN0AZZicLAwicv803z4jdtfQGia1ah1xmdSUTR1uDq7uvAAjPMbA/640?wx_fmt=png&from=appmsg "")  
  
端口8821为被攻击网站端口、端口12485为宝塔端口，输入BT后修改密码然后输入14查看面板信息![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdFgCL1vm2Ppg4j8xt3Uw5ggUG9WZcFib5klQAEjmECQVkzgzxASicMMqw/640?wx_fmt=png&from=appmsg "")  
  
  
查看宝塔WEB日志、可以看到日志192.168.20.1一直在进行疑似扫描操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdOQZLJTlQTylwy7GJwgoAb7Fia5OxYHfysC0GkbW54N0u2FLgJJTrNYw/640?wx_fmt=png&from=appmsg "")  
  
实际上查看操作日志，这个IP是网关地址哈(因为是环境作者模拟复现的)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdRp3aIA0CQ4r0QL0IRqWichGBO9wmj6IPYVutgKibmsWo435BP0RmLPIw/640?wx_fmt=png&from=appmsg "")  
```
2. 分析黑客修改的管理员密码(明文)为多少
答：Network@2020
```  
  
在宝塔面板中点击 数据库-phpmyadmin访问，接着登录后查看库名"kaoshi"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdfQsz6TibpdSqDdLiawMqDXdRzLbGN9kibaslIfwy0d82koEKKe59fVvQw/640?wx_fmt=png&from=appmsg "")  
  
因为题目为用户名被修改，所以查看x2_user表(可视化中没有这张表)，所以需要select * from x2_user去查询(此处是西湖论剑0day，反序列化漏洞)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdF98mPCCxib96KcNd3j5qCWEKEj8LSfv2wOpuGuiaib9Vt5L1dOz6s6pcA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdOFiahgoPK67MOp8J4hMdA8Ce6uKXd1yOSDJINB3ZLNO2F4VqicLqZHzg/640?wx_fmt=png&from=appmsg "")  
  
将查询到的admin(管理员)的密码进行MD5解密后，看到被修改的密码为Network@2020  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdWZia3DvFAVrPEeT9MCQfNAHmVGRCgXEtwibiaxRXmG1UibNdAbNzZq7pvQ/640?wx_fmt=png&from=appmsg "")  
```
3. 分析黑客第一次Webshell的连接URL为多少,将黑客第一次Webshell的连接URL作为 FLAG 提交
答:index.php?user-app-register
```  
  
访问端口8821就是这个业务网站的地址，这里在之前拿到了管理员密码，直接登录后台，写入的webshell  
会进行序列化存储到数据库，在获取模板模式的数据的过程中，blockcontent会被反序列化并将内容赋值给 app/content/cls/api.cls.php中的$tp 最后在进入eval执行了代码![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdw7EOFibiaaibCFFhex4ErcON3zSKOIbeWjK8BkU842rLnAHBqcZrXyxsQ/640?wx_fmt=png&from=appmsg "")  
  
  
存入数据库后，调用位置为注册模板ID为1的地方，即为index.php?user-app-register，  
  
而namespace t是命名空间的声明，防止不同库之间冲突  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMpXSHcaVUvMriclSAzILkfCxpnibALVRQN6jSpZFricJTBpNIJfMHvYd6TM94IicYbmeL14GAzQ5Q7NQ/640?wx_fmt=png&from=appmsg "")  
```
data/compile/content/tpls/master/_cpl_blocks_xxx.php
```  
  
这里是后端程序，负责接收前端来的执行操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdicUG0GHMlDmZkVBAWjeyXsVbgL7UkAthTWCw4AmoTibGjVyEtj5XuzkA/640?wx_fmt=png&from=appmsg "")  
```
然后在
data/html/content/tpls/master/blocks_xxx.html
是前端页面，向用户展现的页面
前端执行向后端发送请求后，后端接收请求并序列化存储数据到数据库
然后相关标签根据ID调用，达到RCE目的
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdfTEGqZH0YYEq6cnTJOKZOED0EvL26bsJ65pBP7V9dnhnReRxRhajVw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdqzqCHh6YJNkhkFBKDk2CibvOuwn0dQldXFMqkQJmCnJ6efiaQl2QVHjA/640?wx_fmt=png&from=appmsg "")  
  
```
4. 分析黑客Webshell连接密码多少,将黑客Webshell连接密码
答：Network@2020
```  
  
这个比较清晰了，攻击者将webshell写入到此处，此功能路由到注册标签，然后在连接的时候执行index.php?user-app-register POST Network2020  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhd4QYH2EkSAnvgLMzicTnJiat6P1SJgvfvEIITXrzFv2MFficBqZoksiaHwQ/640?wx_fmt=png&from=appmsg "")  
```
5. 审计流量包，找到第一个flag文件中内容
答: flag1{Network@_2020_Hack}
```  
  
这里环境作者把流量包放到了root目录下：数据包1.pcapng  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhd65fUA8387aQRoteGGZrwKzqb0rn8eicEhZsg7GeJw2wT15Gy1gTxdug/640?wx_fmt=png&from=appmsg "")  
  
这里使用宝塔直接在根目录下的root目录下载就行，既然给出的题目是上传的文件，直接缩小了范围了，http协议，然后先过滤掉404等状态码或者匹配200状态码  
  
搜索流量包并过滤指定状态码 http.response.code == 200 依次遍历流量后看到flag文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdTTwabofwysIH0T1TdTgSoapUia3h9Xfa22YgU9tr76QNo7GSmRFcSTw/640?wx_fmt=png&from=appmsg "")  
```
6. 分析黑客使用的后续上传的木马文件名称为多少,将黑客使用的后续上传的木马文件名称 作为 FLAG 提交
答：version2.php
```  
  
因为后台传的webshell是路由到注册页面的，所以路径register的特征是蚁剑，接着往下审计流量，看到version2.php流量，请求体内容为加密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdImjGxiajhFxrXcIwxRfdPY0BoZPb7mibyZX0olhj17ZjSPgoZspKpfew/640?wx_fmt=png&from=appmsg "")  
  
首先依次判断一下上下请求，第一二请求一般都是GET，因为冰蝎流量会有一个密钥协商过程，当然冰蝎3以后这个过程没了，但是一些特征还是存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhda4yJysia4HsbJ9CjSoaEkzIy7VC2bH0xiag0DynSOwXbXyicvfCwefibTA/640?wx_fmt=png&from=appmsg "")  
```
在冰蝎3之前呢大概是这个流程
1. 冰蝎请求服务端，服务端收到请求后生成一个128位随机数
2. 服务端将这个随机数写入session，并且返回给客户端(冰蝎)
3. 此时这个不作为执行key使用，而是不断复用以上方法，直到满足特定条件
  以上过程有种shiro反序列化特征
4. 直到满足条件后客户端(冰蝎才会确定这是最终key)
   客户端保存key至本地作为通信密钥，而服务端则在响应包内set-cookie显示
5. 以上不断GET就是在匹配密钥过程，POST则为确定key以后执行命令过程
执行流程：
6. 服务器生成一个MD5的16位数作为密钥，客户端去匹配
7. 匹配成功后，客户端将预执行命令利用AES/XOR加密发送至服务端
8. 服务端接收后对相关加密请求进行解密，然后将执行结果加密后返回至客户端
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdictqrRvABaiaes20bnafvF8XrrwxJctrWGPjIIVUsbKNtdcBTI03YxFw/640?wx_fmt=png&from=appmsg "")  
  
这里上传冰蝎webshell是这个CMS有一个非预期反序列化文件上传漏洞，这里只是验证漏洞的过程  
```
7. 分析黑客隐藏的flag2,将黑客使隐藏的flag2 作为 FLAG 提交
答：flag{bL5Frin6JVwVw7tJBdqXlHCMVpAenXI9In9}
```  
  
这个题其实比较生硬的，它不是shell无法使用工具查找，假如没有特征的情况下，只能挨个去翻代码，而且没说这个flag2是在系统内还是在php文件内，没有上帝视角比较难做  
  
在原WP中flag2在 /www/wwwroot/127.0.0.1/.api/alinotify.php 文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdX7RHyls23pYRZ0a8rvy2iceW3ibNjPicrH0rnGYwAd28h318j1TBTl8PA/640?wx_fmt=png&from=appmsg "")  
  
当然了使用grep -rn是可以遍历到的  
```
8. 分析黑客隐藏的flag3,将黑客使隐藏的flag3 作为 FLAG 提交
答：flag{5LourqoFt5d2zyOVUoVPJbOmeVmoKgcy6OZ}
```  
  
这个题目正常来说，在真实环境可能会遇到，本来我的思路是，他可能会在用户密码文件内，或者是ssh私钥文件或者是crontab文件，结果都没有，我看了眼WP，是在env的环境变量里面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdibAD36B7QfDJRQMa57L3KXicFwtKO4Ca9ia2A2qJfA87cBpkznRHeb9OA/640?wx_fmt=png&from=appmsg "")  
  
其实这一块也没什么毛病，在实战中，攻击者可能会修改环境变量达到劫持命令来进行命令执行  
```
举例说明：
假设攻击者想要在受害者的机器上执行一个恶意脚本 malicious.sh，并且希望当受害者执行 ls 命令时，该脚本被执行。攻击者可以这样操作：
将 malicious.sh 放置在一个常见的目录，比如 /usr/local/bin。
通过某种方式（如钓鱼邮件、网站漏洞等）获得修改受害者环境变量的权限。
修改受害者的 PATH 环境变量，将 /usr/local/bin 放在最前面，这样当执行 ls 命令时，系统会首先查找 /usr/local/bin 目录下的 ls。
将 malicious.sh 命名为 ls 并设置为可执行。
当受害者执行 ls 命令时，实际上是执行了攻击者放置的 malicious.sh 脚本。
```  
  
**0x03 总结**  
  
    我这里根据以上过程大概模拟了一下攻击者思路，毕竟学习为了运用实战，不理解的情况下干学没有意义，当然了思路可能和原作者的思路不同，仅为我自己理解，在现实应急的时候，环境千奇百怪，当前练习的环境仅为模拟，当你在实战的时候可以联动起来，然后猜测攻击者的思路，刷完以后不去思考和学习干刷题为了成绩一样，是没有意义的！  
```
1. 黑客先进行了扫描，然后反序列化漏洞更改了管理员密码
2. 修改密码后，根据CMS序列化漏洞，在后台中对前端注册页面写入了路由webshell
3. 攻击者又通过反序列化phar文件上传漏洞，上传了冰蝎马
4. 后续安全管理员可能会进行查杀，所以攻击者植入了隐藏web后门
5. 在系统内，攻击者在变量中植入了恶意命令，进行命令劫持
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOr39uBgDibn7J5hP3PNvEhdOEY7I3iaEs99NMHR6Tt8w2J0QnoibtMUticPYjyjiaJpcicgiade0QXX1CBQ/640?wx_fmt=png&from=appmsg "")  
  
    接下来是玄机邀请码/注册码抽奖环节、点击小程序直达，转发文章点赞来增加中奖率咯！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNFmaibjiblRPm0aA0rnNUZqJvJrp9GeQ5c8bRZRxdeXJnIFRic8RGuTKycd8meXcoRibTpzMmaGrvjiag/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
