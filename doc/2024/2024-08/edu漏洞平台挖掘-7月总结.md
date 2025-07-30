#  edu漏洞平台挖掘-7月总结   
原创 湘南第一深情  湘安无事   2024-08-23 23:46  
  
声明  
  
**由于传播、利用本公众号湘安无事所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。如有侵权烦请告知，我们会立即删除并致歉。记得点点关注哦！谢谢！**  
**免费送edu邀请码。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjTgnGxC2l2Te3MnoPmWpzuUP4DyAMqyCm2r4YVxcdfCPiaeEYKfibASZDMXKiahLNsibB31ibrhjQ2cLQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
上个月成果展示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjTgnGxC2l2Te3MnoPmWpzu2oROJWgKnVVLcgUXL8WKpfQnl42ex9qe1Ek6QZiblZZ4Xlt2OmP2gjg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjTgnGxC2l2Te3MnoPmWpzuBAfd1bib0BVRzib4HEJELZhA86gRSjice3fQ17haNRW6oIU1QmtgdO0NA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
7月的湘安无事团队，贡献最多的是以下三位同学，可惜他们并没有拿到edu教育漏洞平台的前三，但是也每人奖励了一个KFC  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu3icFHiaNHNMsYCTAXo7hvkmjAI3dAib9YuiaRqr6D2lGq6f3YoZwgGuCeln6CvdeTXwk5icKl9A9WYaw/640?wx_fmt=png&from=appmsg "")  
  
所以8月edusrc排行榜团队人员前三，我们将给第一名送出价值328黑神话悟空，第二名奖励两个kFC,第三名奖励一个kFC。没有人拿到的话就看情况送kfc吧  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKRhz84trN86sia4icVdaKSzKukXhFXaJLKMKKEU4Ysg1AuhHiaI2KBBjlA/640?wx_fmt=jpeg&from=appmsg "")  
  
但是也是邀请了团队HYZZ同学进行长达20分钟的技术分享  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKnljibcrHKZNSMVCxeQW9dsz80OgXibyJGwec8sOkibIUO3wD0dKaeviajw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞分享报告其中一个如下：**  
  
1.某天小帅HYZZ同学  
再鹰图乱逛  
逛到一个管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKBo0prr7obA9zKgfBcNqncibZpFB2jFIbhSibmujPcJNGxzkT5BianoLeg/640?wx_fmt=png&from=appmsg "")  
  
2.熊猫头看到js文件泄露了许多接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKfCxbtOzm8S7wRKHqZIl2eE9zOtQp4ic5J8WuRicfl6S7aR9B5WpaQv8w/640?wx_fmt=png&from=appmsg "")  
  
3.随便测试了几个发现没有权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKoZejpczic6obb7jUxy0kXAI559kYuDSS4I3mNbfyE9FGWzubC5MayZQ/640?wx_fmt=png&from=appmsg "")  
  
4.仔细看接口文件发现大致分为三类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKI3IyZEjR0ZoKUc9vCVcTfQWV6SaUCUAu5eA5ILibERvexJwJESjWkHw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKUVnvAt2GJ8Vz0vnyu78I5vtfZ6KIxqpeq502jqPSgPIbSubX0zgibNQ/640?wx_fmt=png&from=appmsg "")  
  
admin/xxx,  
  
member/xxx,  
  
common/xxx  
  
5.该系统为管理系统，登录账号对应的应该是系统的admin权限，那么则应该还有账户可以对应系统的member权限和common权限，但是围绕系统找不到另外两个用户的登录接口，接口系统功能联想到小程序，直接丢进去搜索找到小程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKniaY2TYOkqWMcuQsjwVzd9V8VMb9FPeicq9eUfaT3R10BW91MU5gmISg/640?wx_fmt=png&from=appmsg "")  
  
6.进入小程序可以看到登录/注册功能  
  
1)随便注册个账号发现需要认证，但是不是该学校校友认证不了，但是已经拥有账户了。  
  
2)又尝试了一遍接口，发现common权限和member权限都已经有了，结合该系统功能点发现认证解锁的权限仅为前端鉴权，注册后的账户直接拥有member权限和common权限，然后开始测试什么接口具有危害  
  
3)然后发现下面这个接口，直接泄露大量的敏感信息，其他接口可以实现越权操作和敏感信息泄露，这里不演示了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKQK5896dnOwia0WPqtonCLKd1liaZSEBFbKNP3UYxAnfQ9riaDXu8nUCvw/640?wx_fmt=png&from=appmsg "")  
  
7.该漏洞厂商已经与我联系，系统已经加上了完善的鉴权，大家就不要再测试了啦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKa0R1jlTVZNBotYjsJF2t1QYgFJQFjJIRczFzhyaBIjsnNxmNfBibFvA/640?wx_fmt=png&from=appmsg "")  
  
  
8.完整的湘安无事团队edu漏洞挖掘技术分享视频-7月，后台回复“  
edu邀请码”，即可获取视频链接观看。视频内容如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYv6UOLWZneicUjMhUlGuzXKKiaV3lTR2yicFfgD2HOABnM8Wn8CaT8W8iagXM2SGxFWtxC4oPPHqW5Jnw/640?wx_fmt=png&from=appmsg "")  
  
  
需要edu邀请码的联系深情哥获取,免费送哦~  
  
nisp+cisp证书报名可联系  
  
内部edu+src培训可联系  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvCicQ0uFJGlricBzMcQSeBRBwP7ibdL6QqtGBFpiaxB3icPcBggPgSlexibAk93icicUDPtOGOz3o3IWUE7A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
