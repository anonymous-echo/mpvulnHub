> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NTU2NjA1Mw==&mid=2247503282&idx=1&sn=13dd8d9fb96d92bb3caa431d4225845f

#  【攻防实战】SQL Server注入之攻防技战法  
原创 平凡安全  平凡安全   2025-07-05 12:01  
  
**「应无所住而生其心」**  
## 「前言」  
  
网络安全技术学习，承认⾃⼰的弱点不是丑事。只有对原理了然于⼼，才能突破更多的限制。拥有快速学习能力的安全研究员，是不能有短板的，有的只能是大量的标准板和几块长板。知识⾯，决定看到的攻击⾯有多⼴；知识链，决定发动的杀伤链有多深。  
## 「1.Mssql报错注入」  
### 「0.判断数据库类型」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDPo6mGObFM6t3Lz9uXib2u9ceibjNXbzlqpsfbG8TldH8RwHfqF7Jl27w/640?wx_fmt=png&from=appmsg "")  
### 「1.爆当前用户名」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDrFSNELib7XNS3Zfiboq1Qiaxag6II5H2NiaYXFCPvAZko72fcypDvfJ3OA/640?wx_fmt=png&from=appmsg "")  
### 「2.爆版本」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDgrvlfRY3ZJWjZYnQLWDa4icvo3zNjyo4H5lzpNZ1pcuSU7UopWXYArA/640?wx_fmt=png&from=appmsg "")  
### 「3.爆服务器名」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDD7t4TLtJg8wO8yWOVibZIg9ToWEKO7vUtict9CxXicILq84TJUSGC30VwA/640?wx_fmt=png&from=appmsg "")  
### 「4.判断数据库个数」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDD90l48r1TXWibp1rC2CQFpXXWs375g1IPFtN8urdqaesaLzItiaVyZcsQ/640?wx_fmt=png&from=appmsg "")  
### 「5.获取全部数据库」  
  
语句只适合>=2005  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDZ1BKjjBtfgs9OduGSoy4iafkFToscx3eiaV6NiaZNYAKWXsaxMnUxtOTg/640?wx_fmt=png&from=appmsg "")  
  
爆当前数据库名：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDRTa5wFQkm5lciaDX8VOibWpaaf4ozaNvjUju7x3iaVQ1G6Sd4KrbwYS8A/640?wx_fmt=png&from=appmsg "")  
  
爆其他数据库名：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDkacztoC0QS3yRRIWtZWwevsNUibaaBWjvYIV6Piam5cSIj65EdOWe2Hw/640?wx_fmt=png&from=appmsg "")  
  
再爆其他数据库：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDjkZ8oCJScNmAW7yicXttHhdj6ucOkicC3W0LbvZMYVd90uDJKbA3twUg/640?wx_fmt=png&from=appmsg "")  
  
爆MSSQL的默认数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDy12ycQXyibVFnHVmgbkKnIEMPXibJr4UiaYCkHrRUhwuwentCcY76IWGQ/640?wx_fmt=png&from=appmsg "")  
### 「6.爆表」  
  
爆数据库所有表（只限于mssql2005及以上版本）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDD0EVWQ5AkRs9QOiciauoA5snm0Zl1q4Tm3IUpwk4c0f6xDP0ffzLDm1Hw/640?wx_fmt=png&from=appmsg "")  
  
爆表：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDCk5OQAE1jXWZhCJLjaHgTdotY5toPe1RPPnW57u3dxIAdv7p1jAUQg/640?wx_fmt=png&from=appmsg "")  
  
爆表：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDZibQtMy41brNUE9FXRSaYACSR7C9OhuwzuwtbPERkFxHZbzobBhH2nw/640?wx_fmt=png&from=appmsg "")  
  
爆其他表：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDD8cRIibPs8zFqdlVSZQjiciavLnXhvgbS3kAdZgQbibjhgUdLdicwjSkS1UA/640?wx_fmt=png&from=appmsg "")  
  
再爆其他表：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDa4mpxTuZqDlEMw5zT5G9Tdhk3VRibqv85SEg1oclgsgR6dBV4BxLgYA/640?wx_fmt=png&from=appmsg "")  
### 「7.爆字段」  
  
一次爆指定表的所有列（只限于mssql2005及以上版本）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDD7Ria3uqxibBH7JWgPhmYp4owOhfmxqk1teTk8BTRkricphp7M2kfcGE1g/640?wx_fmt=png&from=appmsg "")  
  
爆字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDQ63SN04wpRnzNpngGtp2qjqmDic3skBM2t6bIFAzD2aiaRNTCyGdKXGg/640?wx_fmt=png&from=appmsg "")  
  
爆其他字段：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDsUHPib8RIzTdQpSTCSRIWOibH4v0ibIPsbwEFTicUAzx7grawt7pGBprfw/640?wx_fmt=png&from=appmsg "")  
  
再爆其他字段：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDD3RJ9bibMCzpDPeR12EIJamuhCd4FJPiamxJdX3qgwejxU9Gkn91eLicLA/640?wx_fmt=png&from=appmsg "")  
### 「8.爆数据」  
  
逐条爆指定表的所有字段的数据（只限于mssql2005及以上版本）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDa9eQHjXRAicCkXJUlwKf3ICzHg6epCcLWgxV6how9wGMReRLazC2NIg/640?wx_fmt=png&from=appmsg "")  
  
爆数据：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDdXZ4zLE9vjOKkZREtlUT1h25b41qgS3scht2KPApywvynPglIahzqA/640?wx_fmt=png&from=appmsg "")  
### 「9.判断权限」  
  
判断是否是DB权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDnINUgFLrgnJtRNspyiboOMO8vv1or1FKUTybUu1mAL4BAsD3z6IYHKw/640?wx_fmt=png&from=appmsg "")  
  
判断是否是SA权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDojGR3zRrhNtcMp8xMdVKIlrrGXRia72L6EE7oibKuPaEhGbPA3cl2h0w/640?wx_fmt=png&from=appmsg "")  
## 「2.sqlmap工具注入」  
### 「获取全部数据库」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDbJ41nYkF7V1POfMG6dKvVIF8BqYyFKWY6iaNAyr8vLKtZ7qTEfoXQibA/640?wx_fmt=png&from=appmsg "")  
### 「判断是否是dba权限」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDabUicQHfa6SHJjo5IM6sNm6md7LOEGMqHQAgwgJrIoW8CUyVlDRVwJw/640?wx_fmt=png&from=appmsg "")  
### 「getshell执行命令」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDsDicorWRaGzbfwD45zZibZwy7gricMgHlj96pgUwqnpLXGiaoV0aYicP87A/640?wx_fmt=png&from=appmsg "")  
## 「网络安全感悟」  
  
网络安全是一个长期的过程，因为网络安全没有终点，不管是网络安全企业，还是在网络安全行业各种不同方向的从业人员，不管你选择哪个方向，只有在这条路上坚持不懈，才能在这条路上走的更远，走的更好，不然你肯定走不远，迟早会转行或者被淘汰，把时间全浪费掉。如果你觉得自己是真的热爱网络安全这个行业，坚持走下去就可以了，不用去管别人，现在就是一个大浪淘金的时代，淘下去的是沙子，留下来的才是金子，正所谓，千淘万漉虽辛苦，吹尽狂沙始到金，网络安全的路还很长，一生只做一件事，坚持做好一件事！  
## 「攻防交流群」  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpxYSLNvVDicBLvBWnZyw8gDDclnez0GbTj2BrrCCzqmNBicGesYdicTza2dK4Smpj6BHnLbg4lwoLSvA/640?wx_fmt=jpeg&from=appmsg "")  
## 「声明」  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：平凡安全 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
