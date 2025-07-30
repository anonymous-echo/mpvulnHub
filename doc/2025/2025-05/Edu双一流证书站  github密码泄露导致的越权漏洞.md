#  Edu双一流证书站 | github密码泄露导致的越权漏洞   
原创 学员投稿  猎洞时刻   2025-05-11 13:48  
  
```
                              免责声明
本课程旨在培养具备合法合规网络安全技能的白帽子安全研究人员，专注于网络安全漏洞挖掘与防护技术。任何参与本课程的学员，均需承诺遵守国家法律法规，严格遵守网络安全行业的道德规范。
严禁黑灰产及违法行为：本课程严禁任何从事黑灰产、非法入侵、攻击他人系统或从事任何违法行为的人员参与。如果学员在学习过程中有任何违法行为，本课程及相关机构将不承担任何责任。
学员行为与本课程无关：课程内容仅供学术研究与技术提升之用，任何学员的行为与本课程无关，学员需对其行为负责，并承诺仅将所学用于合法的网络安全防护和技术研究。
参与本课程即表示您已充分理解并同意以上免责声明。如有任何疑问，欢迎与我们联系。
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9evFcNH31Pjh0f83GEqsibSQsGS8uUrBPLU6VJbjw8CTibOgsYYOhqqKpaQHb9BicrJcCOYhZG0tYOg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNQyT1w5nApuzicDrQBM0zNqAGx0YPZ1t27bibL8XyMhzcpvuI8gYYYqaQ/640?wx_fmt=png&from=appmsg "")  
  
  
开局一个SSO登录框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNcmlQjuiaA0t7lhBqlOiaYic44W1M7HAnI0hutHicAneP5hwjp2mcr0OD1w/640?wx_fmt=png&from=appmsg "")  
  
通过在github信息收集可以成功拿到默认密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNINwOQOTC3JbFkzdvADhQXYoQDFwyeIJzvTE9OVaicCZfDxLMeiavbZ1w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cN7k5L9j4ByOHnCzZ5cOTVSPYUQJemsu6okML2J6vfTdic7ZMYZKOz6FQ/640?wx_fmt=png&from=appmsg "")  
  
  
拿到账号密码后，可以成功登录学生系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNcHUBSXqAniccJ0fLlZhPUGKZE3ynLI6tRu0G6z1BicMicnkAa7pSjuX0Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
进入vpn后，发现一个系统，使用统一登录。  
  
因为是统一登录，所以使用刚才那个密码仍然可以登陆成功。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNDyEiaOOyceMn6Ooqbxb4pEroQQm4nm3aKFs8uYicjz5H4iaptOgRSQ1Bg/640?wx_fmt=png&from=appmsg "")  
  
漏洞1 越权查询  
  
在shre/list 此接口可获取大量用户 id  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNHJiajArLlcEqcH9AXibtqoLmAVibOXRz77Msicl1c8Q9ibk8azEQjNjDVHQ/640?wx_fmt=png&from=appmsg "")  
  
在file/ls接口，拿到别人学号后，可以越权查看别人的文件信息。  
  
下面是第一个人学号的返回值内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNXdHCE3Vtvic5ZV8rbicibVAicr1NFG1Bp6RicMXMqvxGm50GTxFvwqMe9NA/640?wx_fmt=png&from=appmsg "")  
  
更改学号后，返回包看到的内容已经不同，可以越权查看。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNAH6rltg4ic7B8yFF4IlmKtgrAQshhYmyVs3AmCGfFicPCymxicQMVGRSw/640?wx_fmt=png&from=appmsg "")  
#   
#   
# 漏洞2 越权删除  
  
先使用file/ls接口输入别人学号，可以看到别人的文件信息。  
  
也就是上面的越权漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNLzHI54qstrluRLhPMY6fgeoRSWge4zK94oIokHibqj41LSRBCcJ5RrQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后这里使用另一个接口file/rm ，拿到别人的文件path后，就能够进行越权删除。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNSbTXy0uFxzp9wSGHCIPa3xSObSdEEib2udwOpZjn0TH2yAvykZtJibLg/640?wx_fmt=png&from=appmsg "")  
  
  
再回到之前的file/ls接口，仍然使用那个越权的学号去查询，发现已经删除成功。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9kao7UHfF2hzJ24hTyQ1cNbt9p3VUia7HFJNK4ia3l7s4ErklNduLyYxIrS45qX59a9ESqXb3jUIMQ/640?wx_fmt=png&from=appmsg "")  
  
来自真实的edu证书站的实战案例，感谢师傅观看！  
  
  
     
猎洞时刻第三期开课啦！！价格仅需一千多！课程内容覆盖企业赏金SRC、众测赏金、CNVD、Edusrc、网安岗入职技能培训等~~  
  
2025HVV在即，第三期新增内容也包括了护网培训，让没有参加过一次护网的大学生直接拥有“一次护网经历”！  
  
报名本课程：全天候的技术解答、简历修改、内部众测项目、网安原厂内推、线下岗位推荐、众多安全圈资源！更重要的售后服务~！售后服务！  
  
  
以下为猎洞时刻第三期漏洞挖掘培训课表  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYnKghloAvKFVA1XCTZb7icsSd5MfMibwAqEQYHyLrd9IYI9U9rRcuNhOA/640?wx_fmt=png&from=appmsg "")  
  
  
**第三期漏洞挖掘**  
  
  
  
      目前猎洞时刻漏洞挖掘第三期正在开课中，覆盖企业赏金SRC，众测赏金，线下项目渗透和安全行业工作能力提升、EDU、CNVD，目前价格仅需1K+，每期都可以永久学习，并且赠送内容200+的内部知识星球，保证无保留教学,不搞水课!   
众多学员入职CT、LM、QAX、AH等安全大厂。 酒香不怕巷子深，可以打听已经报名学员，我这边是否全程干货!  
 绝对对得起师傅们花的钱! (以上课表内容并非全部，经常在上课期间添加新的技能方向!)  
  
   
  
来自学员的EDUSRC挖掘成果，一个人单月五百分，十几本证书。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYPgLWriacNzyAksQdXYKsQD7jtMjSF7Y25IBicTG27RfiatM8ic3mbB8WbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALY74flREur5Db0xDhQQNkhPwOQa5m0TMlSYYw6A9df8DaRucXxkalafw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYrO3pcEQavRY72PWs1iahoibBuHYCibm4dicwFVgOWpicZcL0JfxXdhYSTvg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALY0yI2I0ENze3361KDnO6LoSOO8cibXQoA4qrODniayeWmMicnTpcoj5KxQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
来自学员企业赏金SRC、众测赏金挖掘反馈。  
  
低价一千多的课程并不代表内容比市面上几千块的差，打破一分钱一分货的观念！  
  
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
  
不仅仅是挖洞课程，一次报名永久学习，送永久星球、护网培训和推荐、全天技术在线解答、大学生入职规划、技术不错可以安全厂商内推、简历优化修改、安全圈子其他课程资源分享、学不会可以直接语音交流。  
  
目前价格一千多，有优惠，需要报名滴滴我。  
  
更重要的是售后服务！！！不会亏待各位师傅！  
  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6wkBASUnGtVTLJFdwLRiafq5oc8QjqibWWogTsgtJQdlJlODzq0nbtUXQ/640?wx_fmt=png&from=appmsg "")  
  
(课程咨询，加群聊，好友扩列均可加我~)  
  
  
