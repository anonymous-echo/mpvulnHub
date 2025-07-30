#  【漏洞复现】（1day）铭飞mcms-shiro反序列化漏洞复现   
南极熊  WK安全   2023-12-30 09:56  
  
##  双旦活动  2023/12/25-2024/1/1日  
  
**联合活动第二弹（SCA御盾+WebSec）：（1）未加入星球的师傅，只需158元即可加入 SCA御盾+WebSec 星球与专属微信群，加入方式为微信公众号获取并添加任意一方星主后，付费后获得双方星球免费加入链接。（2）已在任意一方星球的成员若有意愿加入另一方星球，只需私聊另一方星主，79元即可进入；（3）活动结束后双方星球恢复正常收费与运营。ps:上述方式皆不支持退款**  
  
**SCA御盾星球介绍详情请访问如下链接：**  
  
**SCA御盾**[星球介绍](http://mp.weixin.qq.com/s?__biz=MzkzNjYwODg3Ng==&mid=2247484051&idx=1&sn=16dd3413d265212ed08ce6d841718d74&chksm=c29d5790f5eade86f19f5f3a7c2e22913eef0ed21605a8f3af966da57dada759dac3357b4168&scene=21#wechat_redirect)  
  
****  
  
**WebSec星球介绍详情请访问如下链接：**  
  
**WebSec星球介绍**  
## 0x01 阅读须知  
  
**SCA御盾实验室的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
  
0x02 产品描述  
  
****  
  
****  
**铭飞mcms是一款基于PHP的轻量级内容管理系统，采用MVC三层结构，具有易用性、可扩展性和灵活性。它提供了丰富的功能和易于使用的界面，使用户可以轻松地创建和管理网站。铭飞mcms适用于不同规模的网站需求，无论您需要管理一个小型博客还是大型企业网站，铭飞mcms都能满足您的需求。通过简单的操作，您可以创建各种类型的内容，如文章、页面、分类和标签等。此外，铭飞mcms还提供了灵活的模板引擎和插件机制，让您可以根据需要进行定制和扩展**  
**。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhTOIl0OnbS42ll1SicO4Sno0C4eubDowU4XeKdXXTujGC456eUttsJeBNb9iaaarshAYFrmwAlDTmQ/640?wx_fmt=png&from=appmsg "")  
  
0x03 fofa语法：  
```
app="铭飞/MCMS"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhTOIl0OnbS42ll1SicO4SnopflHebqIarSFibAHOQ5zibnZJXyF3YvjyIuWfTMGytA04NxA44U4hFYQ/640?wx_fmt=png&from=appmsg "")  
  
0x04 漏洞复现   
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIgicQ3hOib8cnDId9nHhGPq9akxXfUXGAWgMGcPqhJL6DB54WOhcft1QvGHcGMjbUL44an0CXMibicFDA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhTOIl0OnbS42ll1SicO4SnoUAawmrHA1A6xqzRSahWrVbaibxvUaRXPuyq5IepZ6ibUtX6w9xlvZ06Q/640?wx_fmt=png&from=appmsg "")  
  
0x05 修复建议  
  
**1、升级shiro框架至安全版本**  
  
**2、更换aes加密key为自定义key**  
  
**漏洞poc+漏洞批量扫描脚本发布在知识星球**  
  
**明日预告**  
**：（实战SRC）前端加密的用户名枚举漏洞怎么从低危变为中高危？******  
  
0x06 近期发布  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIgicQ3hOib8cnDId9nHhGPq9aa9bOohibPrezRYjDpIJWiaZvbVoicYePl4mDtjrULrW8vZFiciaicExickTyQ/640?wx_fmt=png&from=appmsg "")  
  
进技术交流群可加下方wx  
  
****  
****  
**|**  
**知识星球的介绍**  
  
  
湘安无事星球部分内容预览在线链接  
```
https://docs.qq.com/doc/DUEVsVWhaUk51VUlr
```  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。添加下面wx加星球可享优惠  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
  
知识星球一次付费，后期都是永久免费续费的！！！  
  
加入知识星球之后，可享受其他永久两大圈子"知识大陆+纷传"  
  
一些共享的资源  
```
1.刀客源码的高级会员
2.FOFA在线查询与下载，key使用、360quake、shodan等
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYsHR6CaxF0VtiaIhM3XMm8EjWtzeq6cdnCdf0TsTF7FR6ukMZr4S9KUYDgKicicS9PIHpermh1CgYg3w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
关注下方公众号，输入"  
xaws"即可领取安全类电子书籍一份  
  
  
