#  SRC实战系列-记某次大学漏洞挖掘经过   
 进击安全   2025-02-22 03:45  
  
免责声明  
  
由于传播、利用本公众号所发布的而造成的任何直接或者间接的后果及损失，均由使用者本人承担。LK  
安全公众号  
及原文章作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢大家！！！  
  
  
请勿利用文章内的相关技术从事非法测试，由于传播，利用此文所提供的信息而造成的任何直接或者间接的后果与损失，均由使用者本人负责，文章作者不为此承担任何责任  
  
  
LK漏洞挖掘学院内部学员 -社长师傅文章  
  
0x01 前言  
  
小生也是才学了网安  
2个月，也是想着试一下edusrc的挖掘，见识一下实网的挖掘环境，那么今天就给师傅们分享一些我挖到的第一所大学的的漏洞合集  
，废话不多说，正文  
action!  
  
0x02 敏感信息泄露  
  
首先我使用最经典的谷歌语法  
 site：xxx.edu.cn ( “默认密码” OR “学号” OR “工号”)拿到了部分学生的学号和完整身份证号码，紧接着下一个文件就出现了手把手教我如何登录他们学校的统一身份认证系统，我在此只能说，真的好贴心啊  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFc3CW1ibCouVGS4jtic4TRNI9Zd392Ribs5eSuQ3m351DwrXv9Lbeu2pia9Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcnbxBh7m9ic4qMcAPra1DySfZ4DOgiavLdSrqqJXZXlBiak3Zeic1KcFTPA/640?wx_fmt=png&from=appmsg "")  
  
呜呼，我也是成功进入了其中一位同学的门户网站，低  
危  
漏洞  
+1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcGXnmLRczUx8Ju9JeYqZXYFyVvsmX7sT8n1Sicy4Vme2EF7qUnmOtSpA/640?wx_fmt=png&from=appmsg "")  
####   
  
0x03 druid弱口令*4  
  
当我进去查看功能点的时候，发现目录中含有  
druid，我就想着会不会存在druid未授权访问或者弱口令，  
使用我收集的  
druid接口字典进行拼接测试，发现必须授权访问，随后我直接访问 https://xxx/druid/login.html  
  
admin/123456 弱口令一发入魂，成功进入后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcIznIxCT4yXss2AeqfrNwc2OFEMGbBrjMsxzTYCLzLqsFayIQ11Ys6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFckDB6V9XT9O5J6j92hphSICflDOevaGwIeoUzCmeTnWq4xJOPfNdKSQ/640?wx_fmt=png&from=appmsg "")  
  
在这个  
edu后台站点我总共找了4个druid弱口令，爽歪歪，低  
危  
漏洞  
+4  
  
0x04 弱口令拿下管理员权限  
  
进入这个心理测试平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFc0tvjwj79k3yPUTuLXAnXTW8fs7eam0Q9StOFhy2QxsKYCibjaUdYbXw/640?wx_fmt=png&from=appmsg "")  
  
发现是一个登录框，本来想着先弱口令试一波，然后  
bp爆破一下（还是明文传参），结果admin/123456，然后reporter发包是200，继续发下一个包是302跳转，嘶~ ，好家伙，不会是老天爷赏饭吃，真让我弱口令试出来了，bp直接全部放包，进入后台，拿到管理员权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFc2x09wOU5TW7XLkdbCk0l1B8qQAic6GZibFY4fW5rLzxQcic9huMoYDNAw/640?wx_fmt=png&from=appmsg "")  
  
点击用户管理  
—人员管理—学生—查询  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcCgCYCibCyLZjAoLX3O11bOQUsdXiaNIoicUaN5T45Hwz4noADp1d2qeiaQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到共泄露学生身份证共计  
 20898 条  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcdibVsX2bzmz59Ay0SRMib0j1JJwOza13RrOgBRWTLjvLB75HQ9DnzFsQ/640?wx_fmt=png&from=appmsg "")  
  
点击心理测评  
—测评计划—2023至2024学年春季学期测评—统计  
  
可以看到共计泄露身份证  
 12565 条  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcL6jE5prqpSa8jcqJYOPwmsL3m63hVFT3Q0qp7mODrpBhn1eTMbO9tw/640?wx_fmt=png&from=appmsg "")  
  
共计泄露学生身份证33463 条，高危漏洞+1  
#### 0x05 接管统一身份认证平台  
  
平常我的想法一般都是想着办法进统一身份认证系统，毕竟现在大多数学校都把系统集成化放在后台了，但是今天经过热心姐姐的点播，我在想，既然我在  
001 敏感信息泄露阶段拿到了几位同学的身份证，学号，而且，登录系统一般都会有忘记密码这个功能点呢？那我是不是可以通过同学的身份证给他更改密码，从而进入后台系统，那么，说干就干！  
  
fofa语法搜索 domain=“xxx.edu.cn” && body=“登录”  
  
找到了该大学下的一个统一支付平台，测试了一波弱口令，发现无果  
  
直接点击忘记密码功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcWucjWzNx3XyaWfa5kRWMzib02A4fPqPwaeGnh7Wgich90wEezyULqtwQ/640?wx_fmt=png&from=appmsg "")  
  
哦吼吼，下面这些信息我全都在  
001阶段收集到了，感概一下信息收集的强大  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcPJ2gfNNVjwfvESNibytmjfTPFW5SjXadUm3Y63Y8oVnbHJxMemu9lXQ/640?wx_fmt=png&from=appmsg "")  
  
那么我就可以进去该同学的后台了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7iamFvPHtpLYic7XRyicTU1LFcHtImXNb8rCKE2XiaAhafCjrespvS4NLs7HQJsm4cfmXnMic7mApUfr9Q/640?wx_fmt=png&from=appmsg "")  
#### 0x06 总结  
  
这是小生第一次实战挖掘  
edusrc，没有出什么有技术含量的洞，不过，小生已经很满足了，希望以后技术越来越好，能够挖到更厉害的洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
