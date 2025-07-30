> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247488079&idx=1&sn=364fc8004013684ac3bfc7ab330a7dff

#  无问AI模型实测免杀、资产搜集、应急响应能力  
原创 timi  白帽子社区团队   2025-07-09 09:39  
  
前一段时间无问  
AI  
模型与  
N1  
模型均完成了升级，那么本次就来测试一下他的实际使用效果。  
  
最新的平台地址：http://www.wwlib.cn/  
  
选择AI版的，但是签到功能在旧版(1.0版本)，每天建议是先去1.0版社区签到领积分，然后再回到新版的正常用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wMYvH9cHgvs4zCgtymT6JyjTkUXviaQmIDd4VPzRzxPFck24HhmJkHYg/640?wx_fmt=png&from=appmsg "")  
  
  
本次围绕最常用的三个场景来测试：  
  
（  
1  
）免杀  
  
（  
2  
）资产搜集  
  
（  
3  
）应急响应  
  
1.  
后门免杀  
  
先用  
php webshell  
为例，看看能否绕过  
360  
的查杀。  
  
下方是一个最简单版本的  
php  
免杀  
webshell  
，  
360  
直接就检测出来了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wQnZdMOk6HaibibO1ia5pibrQydwuYExPwhE7jrc0jJpxQfNujwrMFaAQ0g/640?wx_fmt=png&from=appmsg "")  
  
  
那么有哪些对抗方式呢，我们让无问  
AI  
来做一下处理  
  
由于目前无问社区发布了  
2.0  
版本，所以这次我们就用最新的窗口。  
  
需要注意的是，下方要切换到对应的模型，因为默认的是AI帮读，主要用于处理简单问题和文章解析，对于一些复杂问题的表现并不是很好，我这里用的是N1模型，也是目前效果最好的版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wbFzgcYXQMyWJNgBq0GVSk2MOVmBoNoicXtqWrJKpbdq7N4s3FuibHWqA/640?wx_fmt=png&from=appmsg "")  
  
Ok  
，那我们开始让他提供具体的免杀方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5w77UicSjibG0JcgSbv7MhC47u86uUARJ2ZTzfFRnibcL0Konzh5PjxOEdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wxCJFIKsUHKc5yrUEqDqDQh5k2ZPTd38uicV6wyuBbeM5HtFYZaHLkKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wGBtRZsYYzuJibicF8icNpV5h3B7wUbEqqGkeXhnPE8QyJUAXx7vDl3xSg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wIcpwhUM2FerW5lF0C3ZeJFzWU1yrCwibySTZtT2JMaKkZaRu2MfnOtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wmWChKa9FD2dYFec6xdmq5cRj3egRtYof862RDrMiaLAh4ict7tLAwnZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wkwVOIqO5ulSq3Yd4Fk8VGDZCVicxtxQCIg97NFLQTYZMe5vWRdKG6JA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5w4m8mXA2KOetqbuOUhnmd6ibGUUfpvEAOiblYyDmKF1ZNsXjWianQKLmTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wde0V6jibJ6mS6SFJLzpVFUPxY3y5qbRNWcfVJM4ajtlc0B7CKHiaSAAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wzlZJGYZPrncvNWvGF7dEG8y0dJ9mV0Xr4iaibWnbpkkssxIdEuKW63Og/640?wx_fmt=png&from=appmsg "")  
  
这里是给了非常多的免杀方案，当然后续进行了持续对话，生成了更多高级的免杀后门。  
  
最终的效果，成功绕过了  
360  
。整个过程不足  
5  
分钟。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5w1eNrCdYehrbmTIiaEeOJbkmd0pzBPlpjRfTLh5BRlKe7E6icag9tCRpg/640?wx_fmt=png&from=appmsg "")  
  
2.资产搜集  
  
资产搜集的话得切换到无问AI模型  
。整体效果还是不错的，在搜集的同时也对资产列表进行了风险的分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wtGib8GLuQcjfQnpiap3ygBzR2zaW0LuTtArGMAJRlWZSCWODpb8y8cWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wPiafcj3hcVZE6X46zeoqxNU5hqCTCicaRg8bzpQbjAyg7vl3L315ZDQQ/640?wx_fmt=png&from=appmsg "")  
  
  
3.应急响应  
  
这里我让他扮演一个应急响应工程师，给了他一个常见的攻击结果，让他分析攻击者的攻击路径以及排查方向  
  
这里是给了非常多的排查方向，以及详细的操作流程。因为内容太多我只截图了一部分  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wny2wQZT1QiaHJmEYibh3jT7eY7riaDeca9GRIibN9B3GKdiaHcTBoTZvSkg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wPkUflfTwqzAo99xdqHFtDngouq331FyTiabk9EO3rRwukefAEy3GX5g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wqmg1vZxYTgxL9lyibqkBwPibceJcV5Nwict2SXgib4hsm4g9O2w3NYg88w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wYojsmm1R8NibuMIDn2onibphpzTDfria7KDYGsu8abbJQ0ZY6RLVe2iaGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wibWI70ZkicmRnss5xJ9ribfDjHE3PuVFKKHckLwxuKfGtsYdgicCmUsDDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wiarSD3iaAsadRrRHuczdQhyicsTZ3icu6zgANg7IfyIk6Uo2Oznib6PvjLA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wy9IqRBU5AfyRDZMNpfKiaJFvmgOsmHicmicVO6nqQNC5QQaS50Hz4DH9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wUU9GzFJl4CP3TbdO6Oczgsy0Kuzice3OSey9b2eRXKzbh4gGIicQs5Ig/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wUU9GzFJl4CP3TbdO6Oczgsy0Kuzice3OSey9b2eRXKzbh4gGIicQs5Ig/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6kQHUgYxKSYODqib9Kqvl5wtLW8ex8P9bv7ichuDYTdrBIp4ndQFgAWrMhaTjibuOjymB4o2BbzCF8g/640?wx_fmt=png&from=appmsg "")  
  
  
另外平台开放了一些积分，以下是积分码和领取的链接  
  
积分兑换码：  
WUWEN_bQlq10p9k  
  
积分兑换地址：  
  
https://www.wwlib.cn/index.php/gift  
  
  
