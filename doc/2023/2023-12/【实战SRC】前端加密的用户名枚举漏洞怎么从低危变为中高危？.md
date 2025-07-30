#  【实战SRC】前端加密的用户名枚举漏洞怎么从低危变为中高危？   
原创 南极熊  SCA御盾   2023-12-30 10:36  
  
##  双旦活动  2023/12/25-2024/1/1日  
  
**联合活动第二弹（SCA御盾+WebSec）：（1）未加入星球的师傅，只需158元即可加入 SCA御盾+WebSec 星球与专属微信群，加入方式为微信公众号获取并添加任意一方星主后，付费后获得双方星球免费加入链接。（2）已在任意一方星球的成员若有意愿加入另一方星球，只需私聊另一方星主，79元即可进入；（3）活动结束后双方星球恢复正常收费与运营。ps:上述方式皆不支持退款**  
  
**SCA御盾星球介绍详情请访问如下链接：**  
  
**SCA御盾**[星球介绍](http://mp.weixin.qq.com/s?__biz=MzkzNjYwODg3Ng==&mid=2247484051&idx=1&sn=16dd3413d265212ed08ce6d841718d74&chksm=c29d5790f5eade86f19f5f3a7c2e22913eef0ed21605a8f3af966da57dada759dac3357b4168&scene=21#wechat_redirect)  
  
****  
  
**WebSec星球介绍详情请访问如下链接：**  
  
**WebSec星球介绍**  
## 0x01 阅读须知  
  
**SCA御盾实验室的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
  
0x02 漏洞描述  
  
**获取验证码时，无图形验证码校验，破解前端编码后，可批量爆破用户名，获取用户姓名、编号与个人手机号**  
  
0x03 漏洞详情  
  
**1、 app打开后获取验证码时抓包，发现请求数据被加密**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UAAgTXic6IBuE2OOibian0AgplfJmhvlmUIde27ibexjep1IxMO1b0JoH4A/640?wx_fmt=png&from=appmsg "")  
  
2、  
**从手机登录页点击新账号激活时，抓包，在响应包发现其url地址，使用电脑浏览器访问，可以直接访问，则手机端测试转为pc端测试。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UOP1WBtZI2BNwc9dibHZV6bQ6fIHdohbZtsyuAlMYlNKIoO0UU4EkcBA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UAvdYhApurANSvBT8exeHIIA3GUbKkJkZaXUsbnCyc5nNbZJj1MD8hw/640?wx_fmt=png&from=appmsg "")  
  
**3、**  
**查看前端js代码，发现名为security.js的文件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UZtPibn0xq7p6mDEp7yhy6HrhBRkVtdl0JxoMOrHEjQACbriaVf7pibHmQ/640?wx_fmt=png&from=appmsg "")  
  
**4、 发现31行代码就是第1步的请求数据**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UvVxgK4cWWGC4uaeqqnKOTR3PzhHUK8WvPwmtGzeOH9le13ibXRBicF5g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961Uicp2VYZ7ZetgqCtibT1VTIQicZyzVPu9qvpor8zfZFTuyIquPjO1z0vJg/640?wx_fmt=png&from=appmsg "")  
  
**5、向上追溯变量，发现变量传递为data->allParam->signCode->postParam**![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961U1ZGT7wuxdxBKGibNrEq21UrSkGTYA3CXKhwFibj7QF9CGXxc3Mnm4KRw/640?wx_fmt=png&from=appmsg "")  
  
  
**6、 而data变量在html代码里搜索此url的代码也能找到**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UFGicpVzWialLWr1YsqHozoqXtQ1Ixic5U7Ors29ZPhS6HHfdqh36HJvWg/640?wx_fmt=png&from=appmsg "")  
  
**7、由上述代码可知，后续会将json格式转为字符串，即data=’
loginName=base64encode(#loginName)’,尝试用常规的base64编码，结果失败**  
  
**8、 又发现一个名为securityencode.js的文件里有base64编码的方法，由此看出，此处自定义了base64编码，所以常规的base64不行。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961U9uu5DHLSnAj8DMXteVmUAeaPibFLeqP2GR0mDZzv9PvDWXbyMgNEOng/640?wx_fmt=png&from=appmsg "")  
  
**9、调用第8点js中的编码方法，和第5步的逻辑，成功将明文用户名编码成第1步中请求包的加密值，以此逻辑编写python代码，批量枚举用户名**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UD2u7LsibrTtHGbN9padDba1oEaSoFgXPPrrxjlkAmiculo99yReWs69g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UiaVMePQErKic3yMMJic6PFBQCHluFG76hjXU8QUZTlMLQND32Dxey5t7w/640?wx_fmt=png&from=appmsg "")  
  
10、  
   
**使用爆出的用户名去首页登录，到输入验证码的地方，可以在请求查看到明文手机号和authenWorkNo号**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UkXDXgVsDOVBJZrsQSSAK8OKUic2WL24FNcoannBTTpa6bzwzp4OPDiaQ/640?wx_fmt=png&from=appmsg "")  
  
**可以直接pc端访问此url**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961Ufa3ffYhcumJOay2cscHT2ZMLAsEaL3ia4yha2aJkicsaVnrpMQW2tEJg/640?wx_fmt=png&from=appmsg "")  
  
**因此，整个用户名枚举漏洞转变为可批量获取用户姓名+手机号的漏洞，提升为中危漏洞**  
  
0x03 修复建议  
  
**1、 增加图形验证码校验**  
  
**2、 对客户端ip进行频次限制**  
  
**3、 将手机号传参在请求包加密或隐藏**  
  
****  
**更详细报告加python脚本发布在知识星球**  
  
**明日预告：****【专题篇】-python三类上传漏洞poc编写教程**  
  
********  
0x04 近期发布  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIhdmw1hZsKSX5MNOO1c961UZq7kpMqb7TFyYOBsq0ibEK7tvWr7Tbc636Y1DsUEBoPPhdMOJI9N8JA/640?wx_fmt=png&from=appmsg "")  
  
0x05 星球近况  
  
****  
**付费星球**  
  
**以下**  
**活动不支持多**  
**项叠加******  
  
**（1）近期活动：**  
  
**双旦活动  2023/12/2**  
**5-2****024/1/1日：1、联合**  
**活动第二弹（SCA御盾+WebSec）：（1）未加入星**  
**球的师傅，只**  
**需**  
**158**  
**元**  
**即可加入 SCA御盾+WebSec 星球与专属微信群，加入方式为微信公众号获取并添加任意一方星主后，付费后获得双方星球免费加入链接。（2）已在任意一方星球的成员若有意愿加入另一方星球，只需私聊另一方星主，**  
**79**  
**元即可进入；（3）活动结束后双方星球恢复正常收费与运营。ps:上述方式皆不支持退款2、老带新活动通过群里老人进入星球的新人，只需**  
**109**  
**元进入，老人也会得到**  
**20**  
**元现金奖励。加入方式与奖励方式皆通过私聊，不支持退款3、知识星球发放**  
**20**  
**张价值**  
**30**  
**元的假日优惠券，先到先得，优惠券扫码获得**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIiaGpmQJhruycibHOo6b8wkHJH3HqtQbicb3ibTAUCU1HxEKvwgN8qoJyjclobStXRuwlNB7amV4DZVWg/640?wx_fmt=png&from=appmsg "")  
  
**4、通过私聊进入星球的，只需**  
**135**  
**元，但不支持退款**  
  
**（2）星球更新：1、星球付费成员已满150人，正式与2023/12/25日起，进入费用涨价至**  
**149**  
**元。**  
  
**2、星球内即将推出积分玩法，具体加分细节查看星球获悉。每月初评选出上月积分榜前三名发放现金奖励，第一名获得**  
**150**  
**元，第二名获得**  
**100**  
**元，第三名获得**  
**50**  
**元，星主与管理员不参与评选。不得恶意刷屏刷积分，一经发现，取消其3个月的评比资格。发文每人每天不能超过3条，超过3条警告一次且不计积分，多次警告取消其3个月的评比资格。**  
  
**3、元旦、春节。微信群发放**  
**200**  
**元红包一次，按固定时间区间内，筛选出最倒霉蛋子（即红包抢的最少的人）发放鼓励奖，鼓励奖元旦为**  
**200**  
**元，春节为**  
**666**  
**元，如果同时多个人抢到最低红包且数额一样，则按数量平分鼓励奖。**  
  
**（3）加入说明：**  
  
**1.加入收费说明：**  
  
**（1）现阶段扫码加入价格为**  
**¥149**  
**元，300人后涨价至**  
**¥199**  
**元（系统支持三天退款）**  
  
**（2）私聊微信加入**  
**¥135**  
**元，但不支持退款**  
  
**（3）转发任意一篇SCA御盾的公众号至5个50人以上安全群，在公众号加微信后凭截图发放8折优惠券**  
  
**（4）投稿最新漏洞poc或复现分析文章可免费加入1年(每星期限量5人)**  
  
**2. 每逢节假日会发放一定数量优惠券**  
  
**3.每天日更，工作日推送1day或0day,周末推送出货多的nday，期间不定期推送实用工具或脚本**  
  
**4. 进入星球后加群可提前一天解锁第二天的发布内容**  
  
**5.补天半自动化交洞脚本，计划于2024年农历新年后的第一个工作周于微信群推送，价格10-50元视服务而定**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RxxRc1KlrIh1MLtGKWwgG0PsYxrNm1S79fUzHzGzsYn9Gh1aEpTHUIZOZOHZXjGMfrsXED8jKdCx0icnvtZRvGg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
