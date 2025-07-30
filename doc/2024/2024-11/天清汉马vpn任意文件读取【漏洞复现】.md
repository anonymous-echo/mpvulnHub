#  天清汉马vpn任意文件读取【漏洞复现】   
原创 星河  网安探索队   2024-11-30 06:24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点  
击  
上  
方  
公  
众  
号  
关  
注  
我  
们  
  
**建议大家把公众号“网安探索队”设为星标，否则可能就看不到啦！**  
因  
为  
公  
众  
号  
现  
在  
只  
对  
常  
读  
和  
星  
标  
的  
公  
众  
号  
才  
能  
展  
示  
大  
图  
推  
送  
。  
操  
作  
方  
法  
：  
点  
击  
右  
上  
角  
的  
【  
.  
.  
.  
】  
，  
然  
后  
点  
击  
【  
设  
为  
星  
标  
】  
即  
可  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1nvQZWicibYzQ0c9lxg0qwYFdQXYIrYHGj3ZllEBBdfWC5OZK8TkQySicVJ5m77SmkonvicQ2oaldqwNQFQO0ARzhw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x00 免责声明**  
# 本文内容已进行多层信息处理以确保安全。请注意，使用本公众号提供的任何信息所引发的任何后果，包括直接或间接的损失，均由使用者自行承担。我们强烈建议不要利用文中技术从事非法活动。如发现侵权问题，请及时告知以便我们删除相关内容。如需联系我们，请在公众号内点击“联系客服”按钮，感谢您的理解与合作。  
  
**0x01 漏洞名称**  
  
天清汉马vpn任意文件读取  
  
**0x02 漏洞介绍**  
# 天清汉马/vpn/user/download/client接口ostype参数存在任意文件读取漏洞，攻击者可以通过漏洞读取服务器上的敏感文件，包括配置文件、保存的账号密码等敏感信息从而导致进一步攻击。  
  
**0x03 影响范围**  
# 天清汉马  
  
**0x04 网络空间测绘查询**  
# body="select_auth_method" OR body="select_auth_input"  
  
  
**0x05 漏洞复现**  
  
关  
注  
公  
众  
号  
回  
复  
“  
2  
0  
2  
4  
1  
130  
”  
获  
取  
p  
o  
c  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1nvQZWicibYzTEBU4YBAwyA8AgibsIjAe13cgMTYtlE8GZtPrghyv9OLPSuo0dXo1M69Q3sI5HzVWxiaiaHVKSb1uOg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x06 nuclei批量验证（加入纷传获取）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1nvQZWicibYzTEBU4YBAwyA8AgibsIjAe13aOGe1aLdnZ0tYYDRSLgx1Z2eBTBGnq7c2ScwzDJRy8P6EssA1NTzpg/640?wx_fmt=png&from=appmsg "")  
  
**0x07 修复建议**  
  
升  
级  
至  
最  
新  
版  
本  
  
**0x08 加入纷传**  
****  
  
1  
.  
每  
周  
不  
定  
时  
推  
送  
高  
质  
量  
的  
1  
d  
a  
y  
和  
N  
d  
a  
y  
利  
用  
工  
具  
脚  
本  
。  
  
2  
.  
分  
享  
渗  
透  
测  
试  
技  
巧  
和  
内  
网  
横  
向  
移  
动  
经  
验  
，  
让  
您  
在  
实  
战  
中  
游  
刃  
有  
余  
。  
  
3  
.  
与  
圈  
子  
成  
员  
共  
同  
学  
习  
最  
新  
安  
全  
趋  
势  
，  
不  
断  
更  
新  
您  
的  
专  
业  
知  
识  
。  
  
4  
.  
目  
前  
纷  
传  
价  
格  
为  
￥  
9  
.  
9  
，  
星  
球  
人  
数  
达  
到  
1  
0  
0  
个  
后  
，  
费  
用  
将  
上  
涨  
至  
￥  
2  
9  
.  
9  
元  
。  
  
5  
.  
本  
圈  
子  
不  
割  
韭  
菜  
，  
不  
发  
烂  
大  
街  
东  
西  
。  
欢  
迎  
进  
来  
白  
嫖  
，  
不  
满  
意  
4  
8  
小  
时  
可  
纷  
传  
申  
请  
退  
款  
。  
  
[]()  
  
