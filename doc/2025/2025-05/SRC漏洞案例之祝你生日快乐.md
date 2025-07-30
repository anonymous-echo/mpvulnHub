#  SRC漏洞案例之祝你生日快乐   
原创 地图大师挖漏洞  地图大师的漏洞追踪指南   2025-05-08 07:47  
  
# 希望能做你挖洞之路的导航地图 🗺️  
## 前言：从一个小提示开始说起  
  
在SRC的世界里，新手常会问：“我没学过太多代码，能挖洞吗？”  
  
我经常回答：“只要你知道一件事就够了：**做系统不让你做的事，做成了，它就是漏洞。**  
”  
  
今天要分享的这个小案例，算是业务逻辑漏洞里非常适合新手练手的那种类型。我给它起了个名字叫——“祝你生日快乐漏洞”。  
  
听起来像是过生日薅羊毛，但实际上，如果你能系统化地去分析、复现、验证影响，这种“看似无害”的逻辑错误，**完全可以上SRC，甚至评个中低危都不是问题。**  
## 一、生日福利系统：表面的人性化，背后的“逻辑限制”  
  
我们先从生活中一个大家都熟悉的场景说起。  
  
你有没有遇到过这种“生日福利”：  
- 星X克：生日当天送你一杯中杯饮品  
  
- 必X客：生日当天发优惠券，最低消费直接打折  
  
- 某些游乐园、会员制App：生日当天门票减免/赠送虚拟礼物/发积分  
  
这些福利本质上是商家对用户的一种**精细化运营手段**  
：让你觉得“平台有温度”，增强用户粘性。  
  
为了防止被滥用，**系统一般都会把“生日”字段设置为：只能设置一次，之后无法更改。**  
  
但问题就出在这里。  
## 二、灵感来源：“为什么我不能天天过生日？”  
  
某天，我在测试某App时，注意到它注册后会提示填写个人信息，包括生日，写完点确认后，这个字段就从前端UI里消失了。  
  
看起来好像不能改了对吧？  
  
但我的直觉告诉我：“不对劲。”  
  
于是，我打开了Burp，重新查看用户信息修改接口，发现 birthday 字段还在！  
  
我尝试随便修改为另一个日期，提交后刷新页面，**居然生效了！**  
  
我直接笑出声：  
  
**“我今天生日，明天还是我生日，后天依旧是我生日。”**  
  
这就是我所说的“祝你生日快乐漏洞”。  
## 三、具体操作过程（思路解析）  
  
这个思路其实不难，但它的关键在于：你有没有去“试一下”。  
  
大致操作流程如下：  
### 方法一：设置生日时抓包 + 重放  
1. **注册新账号或首次登录时**  
填写生日  
  
1. 打开Burp等抓包工具，拦截设置生日的请求  
  
1. 保存这个请求包，记下字段名，比如是 birthday=1995-01-01  
  
1. 后续想改生日的时候，直接**重放这个请求包，改日期重新发送**  
  
1. 看响应/刷新页面是否更新  
  
有的平台只限制了前端操作，但**后台没有校验是否重复设置**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GHet7yDwHiaMsvVLztGLQdfEIoTbQQbFqwB0E8QMTw7kU36F1HK31Ria8HFNOnrsmu7865yHd5chENpoFaea23icQ/640?wx_fmt=png&from=appmsg "")  
  
### 方法二：修改资料接口直接动手  
1. 登录之后打开“修改资料”页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GHet7yDwHiaMsvVLztGLQdfEIoTbQQbFqyxZm66zoJN4VyIjHpY96b5eFh7kx68FQhUXrRbic2BQqFGyT8Z9VnibA/640?wx_fmt=png&from=appmsg "")  
  
  
  
2. 抓包查看接口：通常是 POST /user/update_profile  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GHet7yDwHiaMsvVLztGLQdfEIoTbQQbFqAJHeAbeibLx8Py9l0etuEicWjpWFt7DgqRbqSo5X8tOzwg7uSKibOc3Pw/640?wx_fmt=png&from=appmsg "")  
  
  
  
3. 看字段里有没有 birthday  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GHet7yDwHiaMsvVLztGLQdfEIoTbQQbFq7qZChgibISQNNhj2o1PhrTaH9rn07A6AUyxUmzmoOGuQYn6ibTVKibic4A/640?wx_fmt=png&from=appmsg "")  
  
  
4. 即使页面上没有生日选项，字段也可能在  
  
5. 改成你想要的生日，提交，测试是否生效  
  
**这种方法的关键点是：**  
  
别被前端限制骗了，重点是抓包，分析接口。  
## 四、漏洞分析与SRC提交  
  
你可能会问：这种能算漏洞吗？提交SRC会不会被说是羊毛党？  
  
答案是：**看你怎么写复现与影响分析。**  
### 漏洞类型：  
- 逻辑漏洞（业务限制未实现）  
  
- 权限绕过（普通用户可以操作受限字段）  
  
### 影响举例：  
- 每天都可以领取一次生日福利（如果平台送的是实物/电子券）  
  
- 导致营销策略失效，平台损失可量化  
  
- 可能被批量注册脚本利用，造成库存被刷、虚假账户增长等问题  
  
### 提交建议：  
  
在复现视频或POC中尽量演示以下内容：  
- 实际领取过程（前一天领过，第二天改生日再领）  
  
- 福利内容展示（截图或录屏）  
  
- 如果能用自动化脚本批量更改+领取，那就是中高危了  
  
## 五、扩展：这种思路可以迁移到很多地方  
  
“祝你生日快乐”只是一个典型案例，这种“系统不让你做的事”却**能通过后门操作绕过**  
的思路，其实可以类比很多其他漏洞：  
<table><thead><tr style="box-sizing: border-box;border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-image: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><th style="box-sizing: border-box;text-align: left;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;font-weight: bold;background-color: rgb(240, 240, 240);"><section><span leaf="">规则</span></section></th><th style="box-sizing: border-box;text-align: left;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;font-weight: bold;background-color: rgb(240, 240, 240);"><section><span leaf="">绕过行为</span></section></th><th style="box-sizing: border-box;text-align: left;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;font-weight: bold;background-color: rgb(240, 240, 240);"><section><span leaf="">漏洞类型</span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-image: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">不是白名单IP不能访问</span></section></td><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">修改X-Forwarded-For头</span></section></td><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">访问控制绕过</span></section></td></tr><tr style="box-sizing: border-box;border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-image: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">只有VIP才能用优惠券</span></section></td><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">抓包直接使用VIP券码</span></section></td><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">权限逻辑错误</span></section></td></tr><tr style="box-sizing: border-box;border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-image: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">活动只能参与一次</span></section></td><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">重放请求继续参与</span></section></td><td style="box-sizing: border-box;font-size: 16px;border: 1px solid rgb(204, 204, 204);padding: 5px 10px;text-align: left;"><section><span leaf="">业务逻辑漏洞</span></section></td></tr></tbody></table>  
当你把这些逻辑当成“游戏规则”，你的目标就是找到绕规则的办法——你就开始像一个真正的漏洞猎人思考了。  
## 六、漏洞不在代码，在生活中  
  
我一直觉得，SRC新手阶段，最容易入门的不是代码类漏洞，而是**逻辑类漏洞**  
。  
  
这些漏洞就像我今天分享的：  
- 简单  
  
- 易测  
  
- 可复现  
  
- 实用  
  
它不需要你反编译、不需要你写EXP、不需要你懂一堆安全原理，它只需要你——**愿意去“做系统不让你做的事”，看看能不能成功。**  
  
祝你也能每天“生日快乐”，早日挖出你的第一个逻辑漏洞 🎉  
## 💬 如果你想了解更多这种“简单但有效”的挖洞技巧  
  
  
对地图大师最新安全研究成果感兴趣的师傅可以访问地图大师个人网站：  
https://www.ditusec.com  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GHet7yDwHiaNIGzdMPPEKc6tYxpA5abHAwyzSaxW99GX9oLhjH6ABLleJSfskEE3sia9U86ew9JVX0t5XFW54aaQ/640?wx_fmt=png&from=appmsg "")  
  
  
