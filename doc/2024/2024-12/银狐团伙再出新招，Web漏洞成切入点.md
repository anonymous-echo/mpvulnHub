#  银狐团伙再出新招，Web漏洞成切入点   
 安全客   2024-12-11 07:55  
  
**01**  
  
  
  
  
**关于银狐**  
  
银狐木马是一种针对企事业单位管理人员、财务人员、销售人员及电商卖家进行钓鱼攻击的恶意软件。该家族木马主要通过伪装成与工作相关的文件，如发票、财税文件等，诱骗用户点击下载和执行，从而实现对目标计算机的远程控制。  
  
  
银狐通常利用“查_看_uninstall.exe”、“11月名单.exe”等文件名来针对性地误导其目标受害群体，并通过QQ、微信等即时通信软件发送钓鱼文件或网站链接，最终实现受害用户的主动执行。  
  
  
**02**  
  
  
  
  
**漏洞挂马**  
  
近期，360发现一个被长期跟踪监控的银狐木马团队在传播手段上又有了新的变化。除了继续通过以往的传播途径外，该团队还进一步新增了对政企网站的挂马攻击。具体而言，他们是**利用了正规网站中所存在的已公开漏洞，将银狐木马和钓鱼页面植入到网站中，再进行传播。**这些政企网站就成了银狐木马的“传播源”，被攻击的网站包括政府网站、企事业单位网站和多家大型国企网站。这些网站的网址，一般会受到聊天软件和安全软件的信任，利用这些网站进行挂马，更容易突破防御进行传播，也更容易获得用户信任。  
  
  
被攻击者利用的，主要是Web应用的上传漏洞。利用图片，附件等的上传接口，很多应用对上传接口检测不严格，对上传文件的访问没有限制，造成攻击者上传病毒文件或挂马页面，之后获取到访问链接，就能够直接传播和发起攻击。  
  
  
目前发现已被利用的网站漏洞有KindEditor、WordPress、UEditor、ThinkPHP等数十款热门Web应用漏洞。以下360近期发现的一些较为典型的攻击案例。  
  
  
**利用****UEditor漏洞****上传恶意载荷到某博物馆页面**  
  
UEditor是国内一款被广泛使用的Web前端编辑器，但其某些早期版本中存在上传漏洞，攻击者则可以利用这些漏洞上传恶意文件，其中也包括了可被执行的恶意代码脚本,攻击者便有机会利用这一点来获取Web服务器的管理权限。  
  
  
在我们的检测数据中，发现国内某博物馆的主页便使用了带有漏洞的UEditor编辑器，这也导致了其主页被黑客篡改并植入了银狐木马。一旦有用户访问该页面，便会执行恶意链接并跳转到某盘的木马下载共享链接进行木马下载操作。  
  
  
由于该网站属于是正规网站，可信度较高，用户难免放松警惕执行了木马，最终导致用户的机器遭到银狐木马的感染和控制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02E8Tickl8zHYU7M4hstwQFKpqJ0MiclQ8CzX9zMfibbMmq9eMI5RDnxOUnA/640?wx_fmt=png&from=appmsg "")  
  
图1. 用户从某博物馆页面下载银狐木马载荷  
  
  
**利用KindEditor漏洞上传恶意载荷**  
  
  
与UEditor有所区别，另一款广受青睐的Web前端编辑器KindEditor在某些版本中存在的上传漏洞仅允许攻击者可以上传.txt和.html文件。但这已然存在着可乘之机——因为这些文件可以嵌套暗链接或XSS攻击代码，所以攻击者同样可以通过构造恶意的html文件来实现跳转、钓鱼等恶意行为。  
  
  
某公司是智慧机器人、智能控制器一体化解决方案的集成商，产品广泛应用于航天、5G通讯、人工智能、医疗设备、轨道交通、智能卫浴、工业控制、新能源等众多领域。根据360大数据排查，该公司的网站便是由于使用了带有漏洞的KindEditor编辑器而导致被攻击者利用挂载了银狐木马，当该公司的客户或远控访问其主页时，便会下载银狐木马到设备中。该网站被植入的恶意载荷列表如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02E5Knvq9ofbV4icCINibBUV5mEAVHPmbnXVDLEibicwoDhmZiaFvg69giaJfOA/640?wx_fmt=png&from=appmsg "")  
  
图2. 被攻击者通过漏洞植入到服务器中的恶意载荷列表  
  
  
同样，受害用户会通过被篡改的页面代码下载银狐木马到本地：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02EicJQHiaqwLf9tt5cd2cls4prmJERr4K4cNyrJGkXVZFrA8BD6KI7FHxw/640?wx_fmt=png&from=appmsg "")  
  
图3. 访问者下载银狐木马到本地  
  
  
更为值得重视的是，被植入到该网站的银狐木马还会利用PoolParty注入技术代替常规的代码注入方法，会在执行后将代码注入到系统进程中实现驻留，规避安全软件拦截。并且会修改注册表启动项和添加计划任务进一步增加自身的“生存几率”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02EatVd8NpicIgFfBfCVQvbic7ibiatBdENNtjVqv2ibT2GDicvLnqXw14LcmnQ/640?wx_fmt=png&from=appmsg "")  
  
图4. 银狐木马在受害者设备中启动  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02EsRW4a4eYJwp08ic7taURVPawO7aM2Y3fEGDicG3VT7kNbJT6hsKQ6XLA/640?wx_fmt=png&from=appmsg "")  
  
图5. 银狐木马修改注册表启动项  
  
  
**利用ThinkPHP漏洞上传恶意载荷**  
  
  
与上述的宽页面编辑器不同，ThinkPHP 是一个流行的 PHP 开发框架，但其某些版本中同样存在任意文件上传漏洞——允许攻击者上传恶意文件并执行。攻击者可以利用此漏洞上传恶意脚本文件，从而获取服务器的控制权、执行任意代码，同样可能导致数据泄露、服务器被入侵等严重后果。  
  
  
360云端大数据发现某直通服务平台由于使用了V5.0.24版本的ThinkPHP而非当前最新版本，导致被攻击者利用挂载银狐木马，被挂载的银狐木马同样也是通过某网盘的共享链接下载到受害者机器中的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02EhEIDSxykcynxqXl5JjnjrT2rCfl1IUMMCtMEUg0XxRUtLt2exLQ5aQ/640?wx_fmt=png&from=appmsg "")  
  
图6. 某直通服务平台被攻击并植入恶意下载链接  
  
  
略有区别的是该链接下载到的是某正规安全终端软件，该终端提供了远程控制功能，此功能允许管理员从远程位置安全地访问和控制终端计算机，从而进行实时的监控和管理。该安全终端被银狐木马团伙恶意利用来实现对受害用户机器的入侵，从而可以控制用户机器，窃取机器信息以及进行进一步的恶意行为。  
  
  
**03**  
  
  
  
  
**安全提示**  
  
  
针对此类攻击，安装有360终端安全客户端的用户无需过度担心，只需正常开启360客户端并确保其防护功能生效，其余的只要交给360即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02EORWhmZfFuwzWAfoqX3tOiaIkl1ic07gAUqluWlhmV2sC2EcQsQ4tiaOjA/640?wx_fmt=png&from=appmsg "")  
  
图7. 360拦截对银狐木马的攻击拦截弹窗  
  
  
对于这类攻击，我们向广大用户提出以下几点安全建议：  
  
  
  
安装安全软件并确保其防护功能已被完整开启，保证安全软件能有效保护设备免受恶意攻击。  
  
  
相信安全软件的判断，切勿轻易将报毒程序添加至信任区或退出安全软件。  
  
  
建议尽可能将网站引用升级到最新版本，并修复已知漏洞。  
  
  
**IOCs**  
  
**样本MD5**  
  
4cf3a577fdd1bdd7d232970c65042a3a  
  
6dc3f6da0a2c7e4a9953b9108fdb296b  
  
50e5f2d31f70aca0c17fda498003fca4  
  
56d5168e68d16cafcae3d0134242887d  
  
e74e418b671845d7e434442c1e4891e9  
  
  
**推荐阅读**  
  
  
  
  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>01</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787459&amp;idx=1&amp;sn=3ce4bc70cc7d74c0d484f1d963142065&amp;chksm=8893bc2cbfe4353ada1a77d6238bb917d94d393c157e33f139c9ec81de232373fac7f41528d6&amp;scene=21#wechat_redirect" textvalue="银狐的反击—模拟点击放行拦截弹窗" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" hasload="1" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;letter-spacing: 1px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">银狐的反击—模拟点击放行拦截弹窗</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>02</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649787412&amp;idx=1&amp;sn=60eff1e08431344a99a3ffccc62c30a7&amp;chksm=8893bc7bbfe4356d51011ad580c70ae32c417b88f2ccad115db203a5931194d09b1cae62475d&amp;scene=21#wechat_redirect" textvalue="再谈银狐：百变木马银魂不散" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" hasload="1" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 1px;font-size: 14px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">再谈银狐：百变木马银魂不散</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr><td colspan="1" rowspan="1" style="border-color: rgb(62, 62, 62);border-style: none;" width="100.0000%"><section><section style="display: flex;flex-flow: row;margin-top: 10px;margin-right: 0%;margin-left: 0%;justify-content: flex-start;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;height: auto;flex: 0 0 auto;align-self: center;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;"><p><strong>03</strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);"><p style=""><span style="color: rgb(224, 224, 224);">｜</span><span style="font-size: 12px;"><a target="_blank" href="http://mp.weixin.qq.com/s?__biz=MzA4MTg0MDQ4Nw==&amp;mid=2247576812&amp;idx=2&amp;sn=219220578363aab542d9de7c549a9783&amp;chksm=9f8d3ce4a8fab5f2d98be5c71718a8889e4d7f8d4ed088bdba323fc12c7b65d00d4d44b49e66&amp;scene=21#wechat_redirect" textvalue="银狐木马阴云迭起" linktype="text" imgurl="" imgdata="null" data-itemshowtype="0" tab="innerlink" data-linktype="2" hasload="1" style="outline: 0px;color: var(--weui-LINK);cursor: default;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 1px;font-size: 14px;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;">银狐木马阴云迭起</span></a></span></p></section></section></section><section style="margin: 5px 0%;"><section style="background-color: rgb(224, 224, 224);height: 1px;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02ELdkF1wogy4RU6heicgrlE4ozKmA0ZGBgmMzETicwEXklPbIUhLakBhOA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb751f2BRPicyega1yYCuQ02EvUEMwl3GGFKOM3WHQ6jkhVTsPF8k4WiaOggq5XV0iaicBQSYqy9y1oR8Q/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
