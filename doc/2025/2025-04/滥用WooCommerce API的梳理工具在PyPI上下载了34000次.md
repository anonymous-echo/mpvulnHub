#  滥用WooCommerce API的梳理工具在PyPI上下载了34000次   
胡金鱼  嘶吼专业版   2025-04-09 14:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
一个新发现的名为“disgrasya”的恶意PyPi包，滥用合法的WooCommerce商店来验证被盗的信用卡，已从开源包平台下载超过34000次。  
  
该脚本专门针对使用CyberSource支付网关的WooCommerce商店来验证卡，这是梳理参与者的关键步骤，他们需要评估来自暗网转储和泄露数据库的数千张被盗卡，以确定其价值和潜在的利用。  
  
尽管该软件包已从PyPI中删除，但其高下载数量显示了此类恶意操作的绝对滥用量。  
  
Socket研究人员在一份报告中解释说：“与典型的依赖于欺骗或输入的供应链攻击不同，disgrasya并没有试图看起来是合法的。”  
  
这是公开的恶意行为，滥用PyPI作为一个分销渠道，以接触更多的欺诈者。值得一提的是公然滥用PyPi来托管一个包，创建者在描述中明确表示该包用于恶意活动。  
  
Socket指出，软件包上的恶意功能是在版本7.36.9中引入的，可能是为了逃避安全检查的检测，与后续更新相比，初次提交的安全检查可能更严格。  
# 模拟购物者验证信用卡  
  
恶意包包含一个Python脚本，该脚本访问合法的WooCommerce站点，收集产品id，然后通过调用商店的后端将商品添加到购物车中。  
  
接下来，它导航到站点的结结账页面，从中窃取CSRF令牌和捕获上下文，这是CyberSource用户用于安全处理卡数据的代码片段。  
  
Socket表示，这两个通常隐藏在页面上并很快过期，但是脚本在使用虚构的客户信息填充结帐表单时立即捕获它们。  
  
在接下来的步骤中，它不是将被盗的卡直接发送到支付网关，而是将其发送到由攻击者控制的服务器（railgunmisaka.com），该服务器假装是CyberSource并为该卡提供假令牌。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEUuG5ETRwmesYtvwNaI3qIrj8ushQqIkicjuGz19thicJibJB8orPVQC7MrbdAcqNHPf8icDCiaZ1h0w/640?wx_fmt=png&from=appmsg "")  
  
向外部发送卡片数据的POST请求  
  
最后，将带有令牌化卡的订单提交到网店，如果订单通过，则验证该卡是否有效。如果失败，它将记录错误并尝试下一张卡。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEUuG5ETRwmesYtvwNaI3q1iaCSic5unZia2osLWUwQIaNGS0L1ibM7xbqibjDQscmvW2QOccIDC2y6sA/640?wx_fmt=png&from=appmsg "")  
  
打印的交易结果  
  
使用这样的工具，威胁者能够以自动化的方式对大量被盗信用卡执行验证。这些经过验证的信用卡可能会被滥用来进行金融欺诈或在网络犯罪市场上出售。  
# 如何阻止梳理攻击  
  
这种端到端结帐模拟过程对于目标网站上的欺诈检测系统来说尤其难以检测。  
  
“整个工作流程——从收集产品id和结帐令牌，到将被盗的卡数据发送给恶意的第三方，再到模拟完整的结帐流程——都是高度有针对性和有条不紊的，”Socket说。  
  
它被设计成融入正常的交通模式，使得传统的欺诈检测系统难以检测到。  
  
不过，Socket表示，有一些方法可以缓解这个问题，比如阻止价值低于5美元的订单，这通常用于梳理攻击，监控多个失败率异常高的小订单，或者与单个IP地址或地区相关的高结帐量。  
  
Socket还建议在结帐流程中添加CAPTCHA步骤，这可能会中断整理脚本的操作，以及在结帐和支付端点上应用速率限制。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/carding-tool-abusing-woocommerce-api-downloaded-34k-times-on-pypi/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEUuG5ETRwmesYtvwNaI3q8eY6cVIHRfBpEPWsictI2Xlvk2zcDoJNOthGSJv2yXiafnqUt1eN5XGg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEUuG5ETRwmesYtvwNaI3qtbnl2IS39iarkK5E0x3JN0zwesy0cwpo69T3LSvMaGNAMkah0pLxktA/640?wx_fmt=png&from=appmsg "")  
  
  
