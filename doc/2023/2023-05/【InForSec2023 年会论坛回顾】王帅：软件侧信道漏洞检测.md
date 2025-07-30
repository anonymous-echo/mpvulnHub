#  【InForSec2023 年会论坛回顾】王帅：软件侧信道漏洞检测   
原创 InForSec  网安国际   2023-05-12 17:48  
  
2023年4月8日～9日，由InForSec、南方科技大学斯发基斯可信自主系统研究院、清华大学网络科学与网络空间研究院、复旦大学软件学院系统软件与安全实验室、国科学院计算技术研究所处理器芯片全国重点实验室、中国科学院软件研究所可信计算与信息保障实验室、中国科学院大学国家计算机网络入侵防范中心、浙江大学NESA Lab、山东大学网络空间安全学院、百度安全、奇安信集团、蚂蚁集团、阿里安全等单位联合主办的“InForSec 2023年网络空间安全国际学术研究成果分享及青年学者论坛”在南方科技大学成功召开。来自清华大学、复旦大学、浙江大学、北京邮电大学、中国科学院大学等66所高校及科研院所的230余人现场出席会议，900余人通过视频会议系统及直播系统参与了本次论坛。  
  
  
我们将对会议精彩报告进行内容回顾，本文分享的是香港科技大学助理教授王帅的报告——《软件侧信道漏洞检测》。  
  
  
王帅老师首先向大家介绍了什么是侧信道攻击。随着各种安全防御技术的提升，在很多情况下攻击者并无法直接的与被攻击软件进行交互，  
侧信道攻击就是在这类场景中的主流攻击方法，简而言之，  
侧信道攻击时通过观察现实中的物理信息的变化，从一定程度上推测出目标程序的一些机密信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyoOD9nlCD79jbE2Pf96hAEUofTBnConOzZBCkIKxvm3cmFtG74BlIWQ/640?wx_fmt=png "")  
  
  
为了帮助大家更具体的理解  
侧信道攻击，王老师向大家介绍了一个经典的基于时间的  
侧信道攻击，如下图的抽象代码所示，当k为1时，进入一个执行比较慢的分支，其他值时则进入一个执行比较快的分支，那么通过观察程序的执行时间时可以推测出k的值是否为1。这个例子看起来很简单，但这种方法可以非常有效的用于攻击RSA加密算法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyGelPA6JSkyK8kErfJCzF5hOcToyMOOaWb9XbQX2IHOzicJMia5OeYgicQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyxF10849qp8sbLIUHgOCBm7s2ia0jiaTV8hHRajBuQicyiaYA6XRUPIbrRg/640?wx_fmt=png "")  
  
  
不过，王老师指出这种基于程序分支的攻击局限性越来越大，很多开发者已经有意的避免将一些机密信息写在条件检查中，因此，王老师又向大家介绍了更加巧妙的基于缓存的  
侧信道攻击，其核心思想在于从缓存中读取数据的速度要快于从内存中读取数据，可以说基于缓存的  
侧信道攻击是目前最流行和最严峻的  
侧信道攻击，比如著名的CPU spectre和meltdown漏洞也使用了基于缓存的  
侧信道攻击，在这种攻击模型下，攻击者拥有和受害者访问相同缓存的能力，从而可以实现监测到被攻击程序执行过程中如何访问了哪些缓存线。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dy30QIYKMaNJAgMtyXy8E8lRMcjRdVsdpHntzjMbwDWu38xt7zItVTkQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyxLqLz3O4bgJqOFSicLv5GeGsGezKm374wvP0IvuiaCgGH89FQ2G9o7tg/640?wx_fmt=png "")  
  
  
在介绍完  
侧信道攻击相关的一些背景知识后，王老师对  
侧信道攻击的研究进行了总结。王老师认为软件  
侧信道漏洞可以分为三个关键步骤，首先是软件的机密信息能够影响程序行为，其次是程序行为影响了物理世界的状态，最后被影响的物理世界的状态能够被攻击者利用去恢复机密信息。目前主要的软件  
侧信道漏洞检测的研究都关注于第一点和第二点，在前两点同时满足的情况下，足以证明一个  
侧信道漏洞的存在，而第三点的研究仍然是比较困难的。接下来，王老师对前两点相关的研究进展和挑战进行了分类介绍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dy38Ko5BWMUvy2FZKe7rC1rvpoRlIDn8icHUDkB5RPgUD5TuVeoF8zaGQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyFtzJ8JLogluPa4zHJeyJficqic8SWG8Ig2jLWDYFgOD6bekBWiac4u7fw/640?wx_fmt=png "")  
  
  
第一个挑战是可扩展性问题，王老师介绍了目前最主流的基于约束求解的  
侧信道密钥信息泄漏，它的主要思想是对密钥相关的程序行为进行形式化的表征，然后再进行约束求解，如果可解，则代表能够得到攻击结果，这种方法是比较直观的，但是存在一个很大的问题就是速度问题，实际执行起来会非常的慢。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSXUtdwOrKtWKl6UdXSF8vZqlAqJVvRDXhuE2TIkRxFwSt7poiaRQLSgfchwA1N09JhD7Nzeib2xVOlg/640?wx_fmt=png "")  
  
  
针对速度过慢的问题，王老师介绍了几篇相关的研究工作，首先是王老师博士期间完成了两篇相关的研究，主要目标就是加速模拟程序与密钥相关的行为。这两篇工作名为CacheD和CacheS，分别从动态和静态的角度进行分析，前者使用染色分析+符号执行做到了较高精度和速度的侧信道漏洞检测，后者使用染色分析+抽象解释（abstract interpretation）做到了较高精度和速度的侧信道漏洞检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyh5P0NyCvic0iaJC0Ot9fdUVodnwNQSJGarpoenFZIfO1q9JP2F9xIdfw/640?wx_fmt=png "")  
  
  
然后是和新加坡南洋理工 Prof. Zhang Tianwei 老师团队合作的工作，使用类型系统（refinement type systems）做到了较高精度且高速的侧信道漏洞检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dy6vttB5pchyfmChoS68RibFJ4p7G1onseLwFtsrab1xQACw5JCEdKfFA/640?wx_fmt=png "")  
  
  
此外，还有和南方科技大学张殷乾老师合作的CipherH，使用动态静态混合分析做到了较高精度且高速的密文  
侧信道检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyPbYMlA70N4GS4fKiarToicEO5toruQtsch2cQlRpNfjVJPDMhiarmkuzQ/640?wx_fmt=png "")  
  
  
针对不同  
侧信道的建模问题，王老师介绍了和南方科技大学张殷乾老师最新合作的，使用符号执行和约束求解技术在可信计算环境（TEE）里面寻找新的  
侧信道漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dysZjI7yw9iaxE18YxkM7tjpF0GFv9ckojWorwRdzO1fNqsV2pWSqYw4Q/640?wx_fmt=png "")  
  
  
定量分析方向，王老师使用互信息熵相关技术去定量估计程序信息泄漏，可以更精确的估计程序各个信息泄漏点的危害程度。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyPCpbtZOgyugKtmXFSCTrTv4R4ac0tNn7gporicKLicyaSS5UlTLxkXaQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyQvFvicH52S9ftdD7Qwx818eILhNSsYFhpaAjicpEsNVGhH2icV7gHdF2Q/640?wx_fmt=png "")  
  
  
在新型数据处理方面，王老师介绍了在人工智能应用场景的  
侧信道攻击研究。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dygmFf6aCUELYrrCcBp0L8MVjWv4JsomahNHptbF0DqsPCUibJUbZzp1A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dy1K7Q2xMpV5FMsNOuAkSKvOwERmWps2YvicWk3TNhuse7ia3WITMLaKZA/640?wx_fmt=png "")  
  
  
最后，王老师分享了自己对于软件  
侧信道漏洞未来研究方向的一些看法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dywgMK3VApjXiajUQQ2icIoSqVjWIMqYXicfERgDlKrc2CBXXS4gWNxNJ7A/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dy0bxrgF9IoErn72bXkO0IlfkatrzWqh5MoOOplsFO0fvDGgf7LyCw5g/640?wx_fmt=png "")  
  
**演讲者简介**  
  
  
  
  
王帅博士现任职于香港科技大学计算机系，曾就读于北京大学、宾夕法尼亚州立大学和苏黎世联邦理工，从事计算机安全和软件工程方向的研究。他最近的研究领域涵盖侧信道分析、逆向工程、供应链安全、人工智能安全和隐私增强技术等。他长期担任CCF-A类计算机安全和软件工程会议的程序委员，他的研究长期获得香港研究资助局等的资助。  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icelxY6ibIXSWXibdQ1VrtXsF7EC9gMj4dyGUCNicKkeBXd5HhGyfXSzxgwRmic8se3ERDVcrTLCjicWZbQR7JpKJ7nA/640?wx_fmt=jpeg "")  
  
  
