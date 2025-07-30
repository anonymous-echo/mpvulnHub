#  红队攻防实战之钉钉RCE   
原创 各家兴  儒道易行   2023-11-23 20:00  
  
我这一生如履薄冰，你说我能走到对岸吗？  
  
本文首发于SecIN社区，原创作者即是本人  
# 前言  
  
网络安全技术学习，承认⾃⼰的弱点不是丑事。只有对原理了然于⼼，才能突破更多的限制。拥有快速学习能力的白帽子，是不能有短板的，有的只能是大量的标准板和几块长板。知识⾯，决定看到的攻击⾯有多⼴；知识链，决定发动的杀伤链有多深。  
# 一、影响版本：  
  
经测试需要钉钉版本< 6.3.25-Release.2149108  
# 二、poc：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMzfcibxOmHzibLFbMpibp34nd2a0TZJqicvAqxh0H1PYkapANia7Bxrcial6w/640?wx_fmt=jpeg&from=appmsg "")  
# 三、触发方式  
```
```  
### 漏洞证明：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMvBupvTOsrLUFDzIThyDeEyJNUlKYChzVEzciaO6BVO0TzOedA2K9ibRQ/640?wx_fmt=jpeg&from=appmsg "")  
# 四、msf反弹shell  
## msf 生成shellcode  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMVgQrAXU2tic5iblKguyFAtFRf617wujeM2SLBJNDeibGS1IwBDIFFY5tQ/640?wx_fmt=jpeg&from=appmsg "")  
## msf开启监听  
```
```  
## 将生成的shellcode替换原shellcode  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMlB5ySCUPhia9TnjW8Tj7siaibgltktQCarAl14wFZBRAibRyy9oYogM9wA/640?wx_fmt=jpeg&from=appmsg "")  
## 需要替换的位置为  
```
```  
## poc:  
```
```  
## 漏洞证明  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMvGnsGvQOLeAlEzqOSmibFmzIrpOntk1TGdvrKrV8u3NVe1qGvtCAbUQ/640?wx_fmt=jpeg&from=appmsg "")  
# 五、cs反弹shell  
## cs生成c#的shellcode  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mM2S9OWu1EQJbhQ0IJ3ZY5HAKVIrmN3c9s8jt94Cgqj3Dj06QH75peYQ/640?wx_fmt=jpeg&from=appmsg "")  
  
不要勾选x64  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMuqSefJ3FEWLaK3W2MjbVRC4xTqjVwicAYTHtENgOoDiafQlRmkbaNpCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
将生成的shellcode替换原shellcode  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMT1spsXCxqoYv8zzjYibysjm3icRcSCkKicYe0rf8awVcGtUfVcDCj8Ryg/640?wx_fmt=jpeg&from=appmsg "")  
## 需要替换的位置为  
```
```  
## poc:  
```
```  
## 成功上线cs  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxlnGfLbyVZqboaDqJK14mMwS2vzI2dK4qZYCiaW1IO128dI5s6aJV6AoPkLTWrBEMH8xj4ribMpI6w/640?wx_fmt=jpeg&from=appmsg "")  
# 网络安全感悟  
  
做网络安全是一个长期的过程，因为做网络安全没有终点，不管是网络安全企业，还是在网络安全行业各种不同方向的从业人员，不管你选择哪个方向，只有在这条路上坚持不懈，才能在这条路上走的更远，走的更好，不然你肯定走不远，迟早会转行或者被淘汰，把时间全浪费掉。如果你觉得自己是真的热爱网络安全这个行业，坚持走下去就可以了，不用去管别人，现在就是一个大浪淘金的时代，淘下去的是沙子，留下来的才是金子，正所谓，千淘万漉虽辛苦，吹尽狂沙始到金，网络安全的路还很长，一生只做一件事，坚持做好一件事！  
  
**免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。**  
  
**转载声明：各家兴 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。**  
```
```  
  
  
  
