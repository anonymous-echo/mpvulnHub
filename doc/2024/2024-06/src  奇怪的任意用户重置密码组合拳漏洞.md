#  src | 奇怪的任意用户重置密码组合拳漏洞   
原创 有恒  有恒安全   2024-06-23 23:03  
  
分享一下之前挖src遇到比较奇怪的任意用户重置密码。该漏洞在是两个不同学校的网站相互配合导致的组合拳漏洞。  
  
**一、收集到的信息**：  
  
1、学校a:https://aaaaaaaa.cn/user  
  
2、学校b:https://bbbbbbb.cn/user  
  
3、a学校与b学校是同一个系统。  
  
4、b学校的学生：杨**，学号与姓名，但不知道密码  
  
5、b学校的学生：于*，学号，姓名与密码。  
  
  
**二、漏洞复现**  
  
1、打开a学校网站，a学校的登录分为两步。第一步输入学号与姓名。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqStpmJB6Cf3GkRAURfBBdFOZSsKU8YgamueAuvYoOXuA8EiaokiapsUnQ/640?wx_fmt=png&from=appmsg "")  
  
当学号与密码正确后再进入第二步输入密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNq94664HkFzrpbNCOY49WPQ9Q9q8NlMgryznPdYb2eZLPkibkODx5yXwQ/640?wx_fmt=png&from=appmsg "")  
  
  
2、在a学校输入信息收集到的b学校的杨**学生学号与姓名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqhmZKcADuknicgUMuKFjVlyIu5kWJAibsWyy6BkUFB2DUYribicpcOhY6qQ/640?wx_fmt=png&from=appmsg "")  
  
下一步显示需要杨**的密码，密码未收集到，但问题不大，从响应包中成功获取到了杨**的userid。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqia4UYnz26TZ52BngnRVMNazBPLkzsWT1LA5sNcl2ZzGIbdJsvYoBu5A/640?wx_fmt=png&from=appmsg "")  
  
3、打开b学校网站https://bbbbbbb.cn/user，系统与a学校网站相同。不同的是，b学校的登录步骤只有一步，即输入学生的学号，姓名与密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNq4k7wibOzfuslgibbB9OVGT7JNMqlKPThZdGicjkIozG2GjF9WBhlTMFgA/640?wx_fmt=png&from=appmsg "")  
  
  
输入信息收集到的b学校学生，于**的学号姓名与密码进行登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqxyU45NuFP38NozHSA75XjfomMxLqL37aXficlH7gP7stLNyq7Bw8ZFQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、在登录后的个人信息设置里，填写好要绑定的手机号验证码信息，抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqCqOulZo6iaibvZATOPjmYafJGaTHibMcGuzZM3vSgGVZTkcOuTx0xEjfg/640?wx_fmt=png&from=appmsg "")  
  
修改userid为从a学校中获取到的杨**userid  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNq0tibeMyOaVWC0gD48DuXn12DIQXKSfXVRkxIrcQLoIM9SRw64icAvc4A/640?wx_fmt=png&from=appmsg "")  
  
响应包显示修改成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqhibW5BMfQT9SE4cPhUArC4Fl2gJ2A4OVPdTqIia4VLQgxdjibusp0gxSg/640?wx_fmt=png&from=appmsg "")  
  
5、打开b学校的找回密码功能，输入杨**学生的学号与刚才越权绑定的手机号，获取验证码信息,新密码为Aa123456@  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqk3XmqFcSibsSCUD7icvicwgAQ63mb50dtvZLh6Dr4zCKgFvNFKwNDiaInQ/640?wx_fmt=png&from=appmsg "")  
  
修改成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqH0hAWQeDtgIpMKiaUpMwmmOSiaoXFl4ziaQ66mdmPLoPz1ZYFesxZaFKA/640?wx_fmt=png&from=appmsg "")  
  
  
6、重新登录b学校，输入杨**的学号与刚才成功修改的新密码Aa123456@。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqb7benDYo841EN1zxe2Hm6Xh9mdUg8icBlwLcKY18J6AEs0qibDFSgTtw/640?wx_fmt=png&from=appmsg "")  
  
成功登录杨**账号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uibic25n4Wib6WWHARsYuvXxyNqXS2meI6JcmGJHUFfmicOKn5T3TqsPAkhOibtcLvSyU6HXZjPqDwmIsgg/640?wx_fmt=png&from=appmsg "")  
  
  
**三、漏洞总结：**  
  
1、a学校登录分为两步，b学校登录只需要一步。且该两个网站疑似共同同一个数据库。2、b学校登录只有一步，无法直接获取到userid，所以可以在a学校中的第一步登录b学校学生，获取到b学校学生的userid。3、通过userid越权绑定手机号，最终实现任意用户修改密码的组合拳漏洞。  
  
  
