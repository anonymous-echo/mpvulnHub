#  Shiro漏洞利用工具   
 黑白之道   2024-11-29 06:18  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
**1**►  
  
**工具介绍**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9cS8WwxeIkv3pnqhdMZKmicFZSAiafd4OyjPq4TPNXX2bUDvqfCs25DJQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
**2**►  
  
**工具使用**  
```
C:\Tools\Red_Tools\ShiroEXP>java -jar ShiroEXP.jar -h

   _____    __      _                    ______   _  __    ____
  / ___/   / /_    (_)   _____  ____    / ____/  | |/ /   / __ \
  \__ \   / __ \  / /   / ___/ / __ \  / __/     |   /   / /_/ /
 ___/ /  / / / / / /   / /    / /_/ / / /___    /   |   / ____/
/____/  /_/ /_/ /_/   /_/     \____/ /_____/   /_/|_|  /_/
                                        

 -be,--brute-echo              爆破回显链
 -bk,--brute-key               爆破key
 -c,--cmd <arg>                执行命令
    --cookie <arg>             携带Cookie
    --gadget <arg>             指定利用链
    --gadget-echo <arg>        指定回显链
 -h,--help                     打印帮助
 -k,--key <arg>                指定key
    --mem-pass <arg>           内存马密码
    --mem-path <arg>           内存马路径
    --mem-type <arg>           打入内存马类型(输入ls查看可用类型)
 -rf,--rememberme-flag <arg>   自定义rememberMe字段名
 -s,--scan                     扫描漏洞
    --shell                    进入Shell模式
 -u,--url <arg>                目标地址
```  
  
爆破key及加密方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9icPMCObBES9eRgblxK8bia4APn63gKsbKqWsZkDyzFR4P3nwDQicjjhNA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
漏洞验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9h5KehjRvfpxFy9icCqK8ub8ZmvbWDqTXhJOBP2Ry0pBGl7HBvF3U99g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
爆破回显链  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9LygDY97c6aeGPIx3WbgBbJic4dANWf0k7r89WXBjlaxiaEpia0wNoH2icw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
命令执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9HW1LetHSmwCn0fOtCpwiapENVrJc4mI9HsbtkayTARw83HicNPYjVkcQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Shell模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9TcAaytwYBBuu1HZstZEJv7FCsL7SC5gicJAVUicCRF1ZpLKefLYia7Qtw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
注入内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9gdNA2MW8dEIlbuWiaddCWGEr7CzMRw55SqXLxd2TkQodKeHdPD1ElVg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**3**►  
  
**PS**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUA9zPJzZ4Ycxvr3D0RAw0ia9V8xKyp8hubMAdesib4zTx3Mk6G8t9dO8icIugI5R17dyvXtl4r3VsRTw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**4**►  
  
**工具获取**  
  
****https://github.com/Y5neKO/ShiroEXP****  
  
> **文章来源：李白你好**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
