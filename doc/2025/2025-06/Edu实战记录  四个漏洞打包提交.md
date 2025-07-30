#  Edu实战记录 | 四个漏洞打包提交   
猎洞时刻  猎洞时刻   2025-06-03 10:46  
  
```
                              免责声明
本课程旨在培养具备合法合规网络安全技能的白帽子安全研究人员，专注于网络安全漏洞挖掘与防护技术。任何参与本课程的学员，均需承诺遵守国家法律法规，严格遵守网络安全行业的道德规范。
严禁黑灰产及违法行为：本课程严禁任何从事黑灰产、非法入侵、攻击他人系统或从事任何违法行为的人员参与。如果学员在学习过程中有任何违法行为，本课程及相关机构将不承担任何责任。
学员行为与本课程无关：课程内容仅供学术研究与技术提升之用，任何学员的行为与本课程无关，学员需对其行为负责，并承诺仅将所学用于合法的网络安全防护和技术研究。
参与本课程即表示您已充分理解并同意以上免责声明。如有任何疑问，欢迎与我们联系。
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9evFcNH31Pjh0f83GEqsibSQsGS8uUrBPLU6VJbjw8CTibOgsYYOhqqKpaQHb9BicrJcCOYhZG0tYOg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
通过前期的信息打点成功拿到了该校某学生的账号密码  
  
 接下来登录统一认证开始大干一场吧！  
  
这里先选择测试该校的学工系统（根据经验  
 学工系统敏感信息是最多的一旦出洞就是高危起步  
）  
  
因为好多功能学生都不能访问，找到一个学生权限可以访问的功能点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9RRz4YRtG3AiaE3vAvvZLMT89Lia3sJuBGoiaybDzt7jKvKusG4312kA7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
点进去一片空白，心凉了一半，只能测一测修改密码  
ing.....好吧没任意密码修改，系统很安全，下号睡觉，文章结束。  
  
怎么可能啊兄弟，包有洞的  
  
选择右上角个人设置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x91bC92SY4UlsiaLp3QHVicxFTBPwPdjdIH3AbrttNxQVEIQdKoNETuc3Q/640?wx_fmt=png&from=appmsg "")  
  
   
  
看了一下，右侧功能点前几项都是跳到对应信息的行数，只有学籍卡，修改记录是新的功能点，点击右侧学籍卡并进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9hHfOjibOGqicpJTbc1UiaTjG9mzkGkMUBobvktJSHtDTdhBicTLeEnVYtA/640?wx_fmt=png&from=appmsg "")  
  
可以看到userid字段我就知道没白来啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9FQyqx1GfT82q5XicErPicBPybfM4SfvtkmgW16UFuxWTmvAEeozwSvicw/640?wx_fmt=png&from=appmsg "")  
  
这里修改为34360做测试  
  
还会有第二个下载数据包  
 同样进行修改（username是下载文件名 可以不改）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9hGCGIziclzmK9trLG5csfibGTBd8SbbHfibNcic7fiaTBiceZicCZqRIlibbUQ/640?wx_fmt=png&from=appmsg "")  
  
oh越权成功，把其他用户的学籍卡下载下来了 高危+1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x91UM0hc5mhJIJABicBsgOjtAzKlCtZcMocKuSUN39ibyI0cvxCSE4ibHKA/640?wx_fmt=png&from=appmsg "")  
  
  
你以为到这里就完事了吗？还有的兄弟  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9FjOglebo2EiaE0afe1bJibbRgemmKnPMs1vREqf42LLebCmYOF1I07pg/640?wx_fmt=png&from=appmsg "")  
  
上面提到的修改记录也得测一测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x94FT54BNO72iaSwYDrdf4dH3NWfPKVE71rRicl4ohyQM7M3qruHPjYaZw/640?wx_fmt=png&from=appmsg "")  
  
改完  
id后，  
不出所料也可以越权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9DGGKS5cB1f3SmWnMiaMYw6GZYHOlgI2R99bCfHEbYRRXoOJheKGTWXQ/640?wx_fmt=png&from=appmsg "")  
  
让我们继续看看还有哪些地方可能存在越权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9aJBpAOKPNBLqib43dSbQwhGhzQM8ZsVRYnOPs0Y3wnzlSIheueFt6MQ/640?wx_fmt=png&from=appmsg "")  
  
这里看到家庭成员、教育经历可以增删改  
  
第一眼就看中了修改功能点，试试能不能遍历出其他用户的家庭成员信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x92zcywHK1T5sC5vFzoTubP19nn9H5ram567JT86h5tVXuC3A4jfTLCg/640?wx_fmt=png&from=appmsg "")  
  
不出意外高危  
+2 成功吧其他用户家庭成员信息越权遍历出来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9HcVxz6Nzlwme8V4sjDT5vK1hVbmBvdPcH2zuzkneIfKo6bfnlOM6IQ/640?wx_fmt=png&from=appmsg "")  
  
继续让我们看看删除功能点（这里建议一般不要测试不可恢复的避免导致不可逆损失  
）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9gUXomaSoYrzmfyKc4sW3MktffpW7df08N9B5icFXacccJ8icSMI9SzyA/640?wx_fmt=png&from=appmsg "")  
  
这里不出意外任意删除  
 中危+1   
  
再跑回去看看添加按钮  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9NNGmYGa4PFVicdxGHBs0vG5diadiclJkGHMAZ52IhJDRud1Fun86pfh6A/640?wx_fmt=png&from=appmsg "")  
  
修改用户账号（学号）即可将信息添加到对应账号内  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x95c4UwgoDkpWTUucVcHfHJsM7an15zpiaicHHs1NpJR9ic0wKPVkec7fAg/640?wx_fmt=png&from=appmsg "")  
  
   
  
最后准备跑路的时候突然看到日历上添加功能，来都来了，点进去看看吧  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x95c4UwgoDkpWTUucVcHfHJsM7an15zpiaicHHs1NpJR9ic0wKPVkec7fAg/640?wx_fmt=png&from=appmsg "")  
  
  
   
  
让我们看看能不能  
x个弹窗进去（这种日程创建都会将用户创建的内容到数据库如果前端过滤不严就可能导致存储xss）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9ccST40F0DibyiaNicFyZ5ib5jzBxIAoFU10zlVibM8zZ5LB0FzffWXMhyiaA/640?wx_fmt=png&from=appmsg "")  
  
哦豁，前端校验，看这样子有戏啊，抓个包绕一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x9ly7IRY07okbBjnev6TwPicvRvWA7dJ72oEadknwLIkXUfvFh97y9xzw/640?wx_fmt=png&from=appmsg "")  
  
再赚1rank，存储xss拿下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8GdJGMibq1fiaAZuvZ24T0x98KDIPGhr63Y5Yx9DEn731d89tcgKbFqicgq2v99vic2UTpaHCiaGpibwhQ/640?wx_fmt=png&from=appmsg "")  
  
****  
****  
      
  
**猎洞时刻第三期漏洞挖掘培训**  
  
  
  
      目前猎洞时刻漏洞挖掘第三期正在开课中，  
覆盖企业赏金SRC，众测赏金，线下项目渗透和安全行业工作能力提升、EDUSRC、CNVD，目前价格仅需1千多  
，每期都可以永久学习，并且赠送内容200+的内部知识星球，保证  
无保留教学  
,不搞水课!   
众多学员入职CT、LM、QAX、AH等安全大厂。 酒香不怕巷子深，可以打听已经报名学员，我这边是否全程干货!  
   
绝对对得起师傅们花的钱! (以上课表内容并非全部，经常在上课期间添加新的技能方向!)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYnKghloAvKFVA1XCTZb7icsSd5MfMibwAqEQYHyLrd9IYI9U9rRcuNhOA/640?wx_fmt=png&from=appmsg "")  
  
也是终于赢得了自己的口碑，众多学员报名后强推“  
涨价  
”的课程，我始终坚信，服务好大家，大家都开心，你们学技术，我也能赚钱，都是双赢，而不是割了韭菜就跑路，遗臭万年。  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicFpowf1mKe20qfMpLBcVUV3GNlUgJqeaXJeNbIzwcDy9Ida8A1CSxspGmFsxvvD8Lic0A0oZTTtQg/640?wx_fmt=png&from=appmsg "")  
  
  
下面是来自学员的EDUSRC挖掘成果，一个人两个月六百分，将近30本证书。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYPgLWriacNzyAksQdXYKsQD7jtMjSF7Y25IBicTG27RfiatM8ic3mbB8WbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALY74flREur5Db0xDhQQNkhPwOQa5m0TMlSYYw6A9df8DaRucXxkalafw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYrO3pcEQavRY72PWs1iahoibBuHYCibm4dicwFVgOWpicZcL0JfxXdhYSTvg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALY0yI2I0ENze3361KDnO6LoSOO8cibXQoA4qrODniayeWmMicnTpcoj5KxQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
来自学员企业赏金SRC、众测赏金挖掘反馈。  
  
低价一千多的课程并不代表内容比市面上几千块的差，打破一分钱一分货的观念！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8yZ3NhhWwLtaxkWNkcegE3RvEoAXXpRU8bGiao5OMyTQ7KgWLiaUoPkEvp7U5taCln3WR4Eev9jIQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHico4s7YfpmcHmWDlhInfXQ3onZicYXP4Uj0ouTBT5XjibfTpA5kiaZzewcDnlKhicLxy12Oa2lm7jhU0g/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYzWcagp19avqg68yMJXCg9StedSvztuxtGT6WGBHBiaibHIYEckicljtdQ/640?wx_fmt=png&from=appmsg "")  
  
  
学员获取万元赏金，一次性回本几倍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYq4mHFyFHQUTQQicUGGnS8DGd6Jbedpz2liaF96icgXhCIDfCeozmuHrcA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYWLzgrwhMOKM4oibbxP1JtZtQIJFAL9hfayESyzYWcUXPyqNMIEE3b6A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
来自学员报名后的真实评价和反馈。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6ExiaaJbSDqQ9FamicjOoN4aVVwjQveKGicwNjicNe87FTDdB7P98yM44qQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
从一开始的疑惑不信任，怕跳入另一个培训的坑，到最后的逐帧学习！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6pZc2LXREMNIpdRNlNGwTLeasLyoPpfJ7XFy1SNRrAVOSA5VXVT0vuA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6MqcwfLpquPZVpCn91la3icYKcEFjaGMLqx4kjG25icSd8yh3n6YgnveQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
每节课都是花费大量时间进行撰写，不仅仅课程全程干货，针对于学员的入职、简历修改、实习和职业规划、工作内推、在线技术解答这些售后服务也一直在认真做。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6wIz6wQlIl3dRCMgYAD4PSfDuAKDWhWRyLiboPFlpmdjFwmI9Gj3MWkQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
课程加量不加价、上述课表中的内容，不代表第三期的全部内容，实际上课会比课表多更多。  
  
课程中还会有更多  
其他师傅的技术分享  
，比如溯源反制、edu通杀挖掘、企业src挖洞新技巧等等...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYwIGqmltkLxbXpaLLEzu6tvafJO5Dms4WGGGtghnKFELWlIPs7VtzRQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
除此之外，包括什么HW和入职简历修改、安全厂商内推等资源、内部众测项目我们团队都是具有资源的！然后还会赠送一个永久的安全圈子(原收费圈)，有大量漏洞实战报告、各种实用工具和安全圈资源！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
**报名课程赠送永久纷传圈子**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6FLfpsSWbNzwzQJza2ibjh5l0t3uicD8DeibFlUfgLvXmn2ZRiadKlnAc6g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6k8MJLUSTKbCwbEwE2yejib6SYER4uY4BtrtZUnb6SeSvuRt3AjLwLvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6rjNT659oVt15pR0AtT7JlmpPbBUs7867ticTdKV1mG1J7Uc6u7Krukg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6DJ5I3VEY7k9SF6SUquUR3YJclSqSdNUCpjSxCcYylIHeicacZexfG5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6VC1D4NCVicfwicEAYsX7wDv3omQiavvibbN2yA5cYfyldFoiaRVNo4vjQMA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6JibDHMf1cBZRic6MoEicRWSc8EICPuAGKMFwq388JKMxyGarX66EdPd5Q/640?wx_fmt=png&from=appmsg "")  
  
  
**报名和咨询课程加我微信**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6wkBASUnGtVTLJFdwLRiafq5oc8QjqibWWogTsgtJQdlJlODzq0nbtUXQ/640?wx_fmt=png&from=appmsg "")  
  
(课程咨询，加群聊，好友扩列均可加我~)  
  
  
  
  
  
