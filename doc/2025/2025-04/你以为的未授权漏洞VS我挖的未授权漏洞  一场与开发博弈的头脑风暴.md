#  你以为的未授权漏洞VS我挖的未授权漏洞 | 一场与开发博弈的头脑风暴   
原创 庆尘qc  Daylight庆尘   2025-04-03 18:19  
  
（后文漏洞为  
靶场环境，如有巧合，纯属雷同）  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
最近有一阵子没更新了，主要是也没研究什么新技术，所以就更新几篇最近打的  
靶场案例，希望师傅们看了之后能有所收获。（师傅们可要好好看了，下次遇见类似的情况你就有思路啦）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
一、挖掘历程  
  
  
经典开局空白页（本人最喜欢的开局页面）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3Yib21iczuYZVQMKoyqKcibzdQZUr5kEVvfHuAJlHZBBC0ykQWdIW270IA/640?wx_fmt=png&from=appmsg "")  
  
这里给师傅们分享我自己挖洞的流程，简单来说就分为三个步骤，如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
1、现有功能点——>2、分析路由——>3、分析接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
现有功能点就是对站点当前所有可见的功能进行漏洞测试，可以看到这个站点首页没有任何功能，但右上角有一个切换租户的功能，点击之后如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo37YbO2ccib5fhibMzI15N8Mj1cMwQHpsXiaMQ6Xk01zib4mGrUobt9X1LIA/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里也没有任何的东西，查看数据包，发现加载了一个查询租户的请求包，也就是对应这里的租户查询功能点  
  
脱敏之后的请求包如下（记住这个API）  
```
POST /api/getTenantList HTTP/2
Host:xxx.com
Cookie:
Priority:u=1,i

["tenantName":"")
```  
  
响应如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo30WRGOntNPPZjbX2PYozFibK1jWVlTErhhic1avd0egnnxKaNibLvgl62w/640?wx_fmt=png&from=appmsg "")  
  
可以看到很明显这里就是查不到数据，只能从tenantName这个传参入手，尝试测试通配符，sql等，发现都没有作用，遂放弃该接口的利用  
  
但从这个接口和响应中我们可以提取到两个最关键的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
1、该接口的功能是查询租户列表（结合功能点与Api分析得知）  
  
2、该接口可以正常使用（也就是我有权限调用这个接口，只是查不到数据而已，通过响应得知）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
我经常会给学生们讲一句话，未授权漏洞测试的终点是“  
接口是否鉴权”，只要接口没有明确提示进行了鉴权，或者无法响应，那这个站点就还有存在未授权访问漏洞的可能性  
  
由于刚刚提取到的第二个信息，所以我继续对该站点的路由，接口进行进一步测试，结果发现内部的其他接口，均显示无权限，回显401  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3qbkHk47amAmL0QZWwXzfTbzFaSDdPJqfZKIGqFb02BUmkJHh6uebcw/640?wx_fmt=png&from=appmsg "")  
  
进行常规的bypass手段之后也无法突破鉴权，那么这个站在我看来就已经无法继续测试未授权了，而唯一的现有功能点也查不到数据，无奈只能放弃该站点的漏洞挖掘，期待下一个站更乖  
  
二、柳暗花明  
  
  
在继续测试了该根域下的三四十个站点之后，某个站点引起了我的注意  
  
该站点是一个学生课程学习的平台，可以看到右上角有一个  
切换学校的功能点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3yibqJvsuia1CaW9Fk0XA3JWuqLYqqrDuRKnDMJmQOibKGlEBwyGSN3vzg/640?wx_fmt=png&from=appmsg "")  
  
点击切换学校，发起了这样一个似曾相识的包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3wyAbKiauYtERnvwiaiaz5vBXQ1BES7ic7yawTaE2ScSXsyjDSTQv6ab1Jg/640?wx_fmt=png&from=appmsg "")  
  
只是因为在history中多看了它一眼，立刻就联想到本文最开始的那个站唯一能用的接口——/api/getTenantList，当然，这里这个接口根据功能简单判断是查询学校列表的含义  
  
然后本站的这个接口响应如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo32xyHbG1eDdkKRSYNCCsIpibciaW8XfxwgY2QMoClcVjiacjZPia4k1fiaqA/640?wx_fmt=png&from=appmsg "")  
  
发现这个站的  
/api/getTenantList响应居然有数据，再观察得知，该响应的格式与最开始的那个站  
/api/getTenantList的接口响应格式相同，只是一个有数据，一个没数据而已  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3XYXooicKh4fPGmuAsP4tr11uUfI9UhJ9yHAP8dCnlFiaFKR423xoqcHw/640?wx_fmt=png&from=appmsg "")  
  
API相同，响应的格式也相同，只是host不同，响应的数据也不同，自然就联想到这两个站之间存在某种关联，所以这里我尝试将第一个站的响应替换为这个站的响应，结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3WiarJ8ps17hevb1RQNBYSibsEdrwtMFibCjVKvhC8HQNPIGfK8eFywWeA/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里被我们改出来了一个租户，由于这里的功能点是切换租户，所以我们尝试点击并切换到这个租户中  
  
过程中加载了一个切换租户的数据包，如下  
```
POST /api/joinTenant HTTP/2
Host:xxx.com
Cookie:
Priority:u=1,i

["tenantNo":"xxxx")
```  
  
然后结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3FZ0Ffe4UUuosSu7joscpcSs7hoO52Kzt0mibkVnfH6hSDhbRFggb4Bg/640?wx_fmt=png&from=appmsg "")  
  
成功接管该租户后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3naqziacCpxyR9fm9cEial9HiahSagjqos9gs2J8a4xxAWURj6U4QnflaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3qoFibOUF9Hw0gyOkA2pkj8ia2wYUG9JRhyxl3Mea5SgpeUNcWcuTSDibA/640?wx_fmt=png&from=appmsg "")  
  
到了这里，洞自然是可以美滋滋的提交了，但这个漏洞内部的逻辑呢，我也希望各位师傅们每次挖到漏洞，都能反问自己这两句话  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
1、为什么这个地方会出现这个漏洞？  
  
2、这个地方正确的开发或设计思路应该是怎样的？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
对于挖到的Top10漏洞来说，这两句话可能很好理解，但对于逻辑漏洞来说，这是一个能够很好的锻炼你挖洞思维的一个习惯，也是我经常给我的学生提到的重点——  
养成属于挖洞专有的思维能力  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
就拿这个案例来说，师傅们看到这里，不妨  
先思考两分钟，能否想明白这个漏洞出现的原因？哪怕是一个大概的猜测也可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
ok，师傅们肯定也思考得差不多了，下面来看看我的想法是否跟你的猜测一样吧  
  
三、头脑风暴  
  
  
由于我们已经挖到了这个洞，所以我们可以反向推理，先在内心列出那么两个问题  
  
1  
  
相同的接口，相同的用户，为什么第一个站点查不出数据，而第二个站点却能查的出数据？  
  
2  
  
为什么第二个站点该接口的响应，拿到第一个站点该接口的响应中，能够正常生效，并且能够正常的点击从而切换进去  
  
首先第一个问题，由于Api相同，响应格式相同，说明查询的是同一类数据，根据Api——/api/getTenantList，猜测两个站点的这个Api功能都是获取租户列表，只不过租户在第二个站有另外一个称谓——"学校"  
  
这里画了一个草图帮助大家理解  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3icruIcia4kYBtW1GAC3u5ygd86N7zTHia5UfwU8biakgPj5ndzic5AHrvFA/640?wx_fmt=png&from=appmsg "")  
  
那为什么相同的用户，在第一个站查不到租戶C，第二个站却能查到呢？  
  
这里其实就可以通过我们这个漏洞来分析，这个漏洞是第一个站切换进租户后，直接就来到了租户后台，说明什么？说明第一个站的目标用户是租户的管理员，因为只有给管理员用的站点，才会一进来就是后台  
  
那第二个站，由于是学员看课的站，租户的称谓变为了学校，切换学校，自然就能够联想到第二个站这个接口的功能是查询当前用户所在的学校（租户），那第一个站很明显就是查询当前用户拥有管理员权限的租户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Sic8MnoJmpJGKzDY7ByUgDExdwUicJRqia5sYJnuoyy7PhiaHWISenULgL6icUvD9n68uvQAnHAoqMcluVsLzvphgEg/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/uG20iccSfcGUv6abf1XgcIic5cPKjfBIViaAfrBdVUXysgwsIaINS87ibNt5QrxLEp9VnF3nHfVrTiamcdJxSNZH5Qw/640?from=appmsg "")  
  
也就是这两个站，虽然都有这个接口，接口获取的数据类型也一样，但站点针对的用户（也就是使用群体）不一样，一个是  
针对租户的管理员，一个  
是针对租户内的用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5ZYUhd5AGgcmF8LI1Ct6uNhPrTHic8HAJqic9Ye0yplmnTbwjOBrswfhib4ojyDa216YsgBwDVJskov9YgW30bPKQ/640?from=appmsg "")  
  
  
，继续完善上图，图例展示如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo37DEo9Hopj0tcHx3qQicDDje8jO9iaebayrHLCC8nc6wkdOg6Xu3Q3kwg/640?wx_fmt=png&from=appmsg "")  
  
这样是不是就看的很明显了，并且第二个站是可以公开注册的，也就是你注册了第二个站点，你就成为了租户C的用户  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/uHwLXtyH4IXTars0DEAdy9nZcUtFcGrTy3nibexVh7BkBPMPp5nLfNgt67b5GWcgVibZsbUSHhKbtb6Eibh4vBoiaLfySz3fSygp/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/dx4Y70y9Xcs692v9TjnicxJEZft7mP8uWicBRPuXXzZg069MvuoD4NP9L3WJiaoqponicCib5DMjypusYpLvEsR5g11bPZsUtwfjB/640 "")  
  
  
  
  
对一个站来说，只有租户C的管理员admin来到第一个站，调用该接口，才会查询到租户C，而用户u1，u2等，来到站点A时，由于不是租户C的管理员，所以是无法查询到租户C的；  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/GPyw0pGicibl6FlfJiaNBkMPMFyFOibLIWIcnofJD9HFIEkZM5SEbOlmbksIpNdHnJna42D5LSLYtEA7cbicE6qBeJv0fJ8eeZjfM/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/ZqDaDiccbgkhBmJZvPXtaUAefuaoJCVTKXplxCtc9ibiav0toECE9GgicrEgxdtJOMFHDgLu3CN01gofEcWnI72wNtR2AicveephI/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/uHwLXtyH4IXTars0DEAdy9nZcUtFcGrTy3nibexVh7BkBPMPp5nLfNgt67b5GWcgVibZsbUSHhKbtb6Eibh4vBoiaLfySz3fSygp/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/dx4Y70y9Xcs692v9TjnicxJEZft7mP8uWicBRPuXXzZg069MvuoD4NP9L3WJiaoqponicCib5DMjypusYpLvEsR5g11bPZsUtwfjB/640 "")  
  
  
  
  
  
但对于第二个站点来说，租户C内的所有人（包括管理员和用户），来到站点B调用该接口，都是可以查询到租户C的，因为他们都在租户内  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/GPyw0pGicibl6FlfJiaNBkMPMFyFOibLIWIcnofJD9HFIEkZM5SEbOlmbksIpNdHnJna42D5LSLYtEA7cbicE6qBeJv0fJ8eeZjfM/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/ZqDaDiccbgkhBmJZvPXtaUAefuaoJCVTKXplxCtc9ibiav0toECE9GgicrEgxdtJOMFHDgLu3CN01gofEcWnI72wNtR2AicveephI/640 "")  
  
  
所以刚刚的第一个问题，我们是不是就已经分析清楚了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3SdGbUWazJkv2yUVetPnSrpIXcVmksjV8C2X7c8J7gbcUmhf80ibQ0ibA/640?wx_fmt=png&from=appmsg "")  
  
答案就是  
由于两个站点面向的使用群体不一样，一个是租户的管理员，一个是租户内的用户  
  
那现在继续来到第二个问题  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3Vv8vibuk8By4noGKyCtXMo6fZaEibvsAD8IeHoczpFAZNdjS8CbC55tg/640?wx_fmt=png&from=appmsg "")  
  
看到这里就有师傅会问了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uNcARtib3nn33UrPuIUkXyqKZJsMD397fjlIdeiaeibXCAMY1f9xHD6kia6y83ktsz8THCWhueNODT7wKzfctmwZfg/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/c6gqmhWiafyoflTUVXTAB2ofQicyAq1m1AZDspXla53SIvicicjbupP5oaDQqKGdUYZSsCa5wF0jhSlbq30uX7M8aQ/640 "")  
   
  
这个改响应只是把前端改出来了，为什么你点进去就能接管后台呢？并且你之前明明说了这个站的接口你是没有权限的呀，访问的时候都是401  
  
  
   
且看我娓娓道来   
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHPicsvHJNw24sa8QTMZOa4uVYpzmZmLpFzuIAhG8K2VV9iaeeNAoEDDsoeu6fZn48UJNjCDKou82lg/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHPicsvHJNw24sa8QTMZOa4uRG4vAqMImYXic04WCo9MzhFr2xLibUUamkHGK33GRSaretuAuNXOazEQ/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uNcARtib3nn33UrPuIUkXyqKZJsMD397fjlIdeiaeibXCAMY1f9xHD6kia6y83ktsz8THCWhueNODT7wKzfctmwZfg/640 "")  
  
  
  
   
  
上面我说了，把响应改出来，点进去的时候加载了一个切换组织的请求包  
```
POST /api/joinTenant HTTP/2
Host:xxx.com
Cookie:
Priority:u=1,i

["tenantNo":"xxxx")
```  
  
就是这个请求包赋予的我权限，从而导致我开始有权限访问我所在的租户后台，这下师傅们明白了吧  
  
那现在整个流程分析完了，请师傅们思考一下，导致这个漏洞的原因是什么？正确的设计思路应该是怎样的？  
  
四、原理分析  
  
  
首先导致这个漏洞的原因，其实就出现在切换组织那一步，也就是这个赋予我管理员权限的包  
```
POST /api/joinTenant HTTP/2
Host:xxx.com
Cookie:
Priority:u=1,i

["tenantNo":"xxxx")
```  
  
为什么说问题出在这呢？首先来看看在开发眼中这个站点A我们的正常使用流程是什么？  
  
开发眼中的管理员：  
```
管理员admin调用该接口——>查询到租户C——>切换进租户C——>进入租户C的后台
```  
  
开发眼中的普通用户：  
```
用户u1调用该接口——>查询结果为空——>撤退
```  
  
然后开发内心暗自窃喜  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uNcARtib3nn33UrPuIUkXyqKZJsMD397fjlIdeiaeibXCAMY1f9xHD6kia6y83ktsz8THCWhueNODT7wKzfctmwZfg/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/c6gqmhWiafyoflTUVXTAB2ofQicyAq1m1AZDspXla53SIvicicjbupP5oaDQqKGdUYZSsCa5wF0jhSlbq30uX7M8aQ/640 "")  
   
  
开发：“我这个站的权限策略想的太周到了，写的真好，小小黑客，不足挂齿！晚上奖励自己吃顿好的”  
  
  
   
庆尘：你先别急着奖励自己，我有话要说   
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHPicsvHJNw24sa8QTMZOa4uRG4vAqMImYXic04WCo9MzhFr2xLibUUamkHGK33GRSaretuAuNXOazEQ/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uNcARtib3nn33UrPuIUkXyqKZJsMD397fjlIdeiaeibXCAMY1f9xHD6kia6y83ktsz8THCWhueNODT7wKzfctmwZfg/640 "")  
  
  
  
   
  
那经过我们修改了响应包，现在的流程变为了什么呢  
```
用户u1调用该接口——>查询到租户C——>切换进租户C——>进入租户C的后台
```  
  
到这样我的想法是任何用户来到站点A，通过改响应包的方式，都可以进入租户C，从而接管租户C的后台  
  
这么简单就分析完了，真是一场酣畅淋漓的博弈啊，为了验证我的猜想，我用另外一个账号尝试复现该漏洞，诶，改响应之后尝试切换到这个组织，发现进不去，也就是下面这个接口  
```
POST /api/joinTenant HTTP/2
Host:xxx.com
Cookie:
Priority:u=1,i

["tenantNo":"xxxx")
```  
  
提示我401，我的第一个账号明明不是租户管理员，可以调用这个接口，第二个账号也不是租户管理员，为什么不能调用这个接口呢？  
  
最后发现，我的第二个账户，并没有注册过第二个网站，也就是那个课程学习平台，所以不在租户C内，到这里我就明白了，错怪开发了，原来开发是做了校验的，那就再来猜一猜开发的心思吧  
  
首先是前面的流程  
```
租户C的管理员admin调用该接口——>查到租户C——>点击尝试切换到租户C
```  
  
到了第三步，其实开发就默认你能通过这个接口查到数据，也就是你是某个租户的管理员，但为了防止你进行越权进其他租户的后台，所以当你切换租户时，会进行校验，如下  
```
点击尝试切换到租户C——>校验当前用户是否在租户C内——>允许进入租户C的后台
```  
  
我只能说开发到了这，为了权限的安全策略已经算是煞费苦心了，两层校验，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640 "")  
  
第一层：/api/getTenantList（区分了管理员与普通用户）  
  
  
第二层：/api/joinTenant（区分了当前租户与其他租户）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640 "")  
  
  
  
  
  
第一层校验通过，说明是管理员，第二层校验通过，说明是所在租户的，那连起来不就是所在租户的管理员吗？然后开放权限给你，Good！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaqjXT4YxgHVARD1NNv0RvKicicC9nrQoyuAkCxuhSCBWfPpVVAicTJiag1j3lFEjwj45aKM4ftrqUS6A/640 "")  
   
  
  
开发：多么完美的权限策略，真是一场酣畅淋漓的开发啊  
  
  
   
庆尘：且慢！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaqjXT4YxgHVARD1NNv0RvK6akibVdClZdRkmpR4whadQZ6NcRocrnarhuDU35km6HSEPYse8FqcEQ/640 "")  
   
  
我承认阁下的两层校验很强，但我这里还有简单又强势的挖洞技巧  
  
仔细观察，我们的修改响应包，实际上是在做什么？其实就是在绕过第一层校验  
```
/api/getTenantList只有管理员的响应才有数据
```  
```
我手动给/api/getTenantList加上响应=我也有响应
```  
  
所以  
我==管理员，第一层校验通过  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/LianbibNTn3Ns455IPTPVwfkoibGedrmpxn8FnwlbKLur87Z6HRrjYicNN8lhdgzTEPiak9AYO5HslVhvNXicKAgWeGA/640 "")  
  
  
来到第二层校验，判断我是否在租户内，我上面讲了，只要注册了第二个站点的用户，都在这个租户内，所以当然在，就成功获取了后台权限  
  
所以这个漏洞的核心分析：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640 "")  
  
1、导致该漏洞的根本原因：用户切换到租户时  
只校验用户是否在租户中  
  
  
2、正确的写法或设计逻辑：用户切换租户时需要校验当前用户是否在租户中，  
并且判断是否为租户的管理员  
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640 "")  
  
  
  
  
  
到这里，就是真的分析完了，没有反转了哈哈，是否跟师傅们的猜测一样呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaqjXT4YxgHVARD1NNv0RvKicicC9nrQoyuAkCxuhSCBWfPpVVAicTJiag1j3lFEjwj45aKM4ftrqUS6A/640 "")  
   
  
  
开发：我服了哥，求你别挖了，今天领导又要让我加班了  
  
  
   
小庆：修复策略都给你写的清清楚楚，叫我雷锋  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaqjXT4YxgHVARD1NNv0RvK6akibVdClZdRkmpR4whadQZ6NcRocrnarhuDU35km6HSEPYse8FqcEQ/640 "")  
   
  
看完了觉得有收获的师傅可以点个赞支持一下，一起期待下次更精彩的案例吧，最后，希望师傅们都能到越来越多的漏洞！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mK8kXuuyDkib8DZR1jiaQSRRpQMHtOeSo3HoibIEVtuUTTZ3AHVAuDQ2lMdiafa5YcgBr8dT5KOmKjHaykCcXoX2Ug/640?wx_fmt=gif&from=appmsg "")  
    
  
最后插个广告：本人亲带SRC课程，想咨询课程的师傅可以在公众号联系我哈（混口饭吃）  
  
