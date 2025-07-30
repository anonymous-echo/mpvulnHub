#  【0day】某州数码DCME-320存在前台任意文件读取漏洞   
原创 Mstir  星悦安全   2024-12-16 04:23  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**DCME-320是北京神州数码云科信息技术有限公司采用MIPS多核高性能处理器，针对多用户数、多流量、多业务种类的业务需求而推出的新一代高性能互联网出口网关。**  
  
**Fofa指纹:"style/blue/css/dcn_ui.css"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yeb2hj5sX4XIsNQAZhnt9HzZ3njgmZdeI7UDlpF1TNS5fe7avIXF4Gg/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yWQJJI70Qem6jOryTVlHnGvy0CGicu7TVjCdpgqb5JlTRcRhdQtEgKZQ/640?wx_fmt=other&from=appmsg "")  
## 0x01 漏洞复现  
  
**位于 /xxxxx/xxxx/xxxx/xxxxx.php 文件中存在 File_get_contents 函数读取文件，且传参均可控，导致漏洞产生.**  
  
**Payload:**  
```
POST /xxxx/xxxxx/xxxxx/xxxx.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh,en-US;q=0.9,en;q=0.8,zh-TW;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 29
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=87bb250979fc82ca898020dfcdadeaf3
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36

详细EXP请见文末!详细EXP请见文末!
```  
  
详细EXP请见文末!详细EXP请见文末!  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2y4NdCHIW9FjrIUH2Dic9r7Cbu7vibwaYT483aM6nSFA5cGxD1ibfejvgFw/640?wx_fmt=png&from=appmsg "")  
  
**可直接读取/etc/shadow文件，DES能直接解密出设备密码**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yafmK6GLyeMYcszTibb0mh7nKDumJG1uEphb0xNK5InNBNP45Z0w2kMA/640?wx_fmt=png&from=appmsg "")  
## 0x02 纷传圈子  
  
  
完整Exp及源码已放在纷传圈子中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有1700+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**5，Fofa API 高级会员Key共享**  
  
**圈子目前价格为88元，现在星球有500+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于12.08日更新**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMxmfGhcPzwxUyCuibfT7IiaSgpfMX4I18XQ9zd2thgFV1sZZc3fg1vn2w/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Fofa 高级会员 Key****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yh7LPSCjwdicjVT9I5kmk5d53XibibUmzz037tTfQx5prf7j21ed3oVTkQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上百套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通源码网VIP，已开通各大源码站VIP**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
