#  全球科技巨头隐秘监视数十亿Android用户，滥用系统漏洞跨端追踪长达八年  
 安全客   2025-06-09 08:37  
  
近日，一项由西班牙 IMDEA 软件研究所牵头的学术研究引发全球安全圈关注。研究指出，**全球两大科技巨头——美国的 Meta 和俄罗斯的 Yandex，借助安卓平台的本地通信机制，绕过系统权限控制与用户隐私防护，悄然实现了网页与 App 之间的 ID 跨端绑定与行为数据融合采集。这一机制已持续多年，影响或涉及全球数十亿 Android 设备用户。**  
  
  
在未经过用户授权、未告知、甚至未被浏览器或系统检测的情况下，这一机制可实现网页访问行为与 App 数据的绑定，使平台可以精准识别用户身份、构建完整画像。更严重的是，一旦该机制被恶意应用程序利用，可能造成浏览记录、用户行为等敏感数据的系统性泄露。  
  
  
01  
  
**滥用 localhost 通信：**  
  
**绕过隐私边界的跨端追踪**  
  
  
**技术原理简述**  
  
研究显示，Meta 和 Yandex 分别在其网页追踪脚本（Meta Pixel 与 Yandex Metrica）中引入了“web-to-native”桥接机制。这一机制通过**监听 Android 设备上的 localhost 本地端口，在不需额外系统权限的情况下，将网页端 Cookie、追踪 ID 或用户行为信息，通过 HTTP 或 WebRTC 通信通道发送至本地 App，再由 App 将信息上传至服务器。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5GCulQvNeNJ7uBQATIondnQG3IKFT9Lo3p9YVBQkZNxkADUnNrJXkCUvjKDRxicThqeyicJajVfzsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5GCulQvNeNJ7uBQATIondnV1ibpicgfAXjeruXnDTRnPIEnd883G4hq9sRgydkPOyzIdu9Beo4JFtw/640?wx_fmt=png&from=appmsg "")  
  
  
在 Android 平台中，应用之间本应被严格隔离，浏览器与本地应用也默认处于沙箱环境，无法直接通信。但这两家厂商**利用 Android 浏览器默认允许发送 localhost 请求的机制，构建了一个隐蔽的 ID 同步与行为收集通道。**  
  
  
研究人员指出，这一技术绕开了 Android 广告 ID 重置机制、浏览器隐私模式、Cookie 清除策略、App 间权限沙箱等一系列设计初衷为保护用户隐私的机制，形同“绕过所有防线的隐秘通道”。  
  
  
**攻击面外溢**  
  
更严重的问题是，一旦攻击者开发了监听相同端口的恶意 Android 应用，即便用户未安装 Yandex 或 Meta App，也能复用该通信机制，监听用户浏览记录。  
  
  
换言之，只需安装一个权限极低的恶意 App，即可在用户毫无察觉的情况下，劫持来自数百万网站的访问记录数据。  
  
  
目前，研究团队已在 Chrome、Firefox、Edge 等主流 Android 浏览器中验证了这一监听行为确实发生，且**在正常和隐私浏览模式下均无法阻断**  
。只有 Brave 默认阻断 localhost 请求完全免疫该机制，DuckDuckGo 浏览器因封锁部分 Yandex Metrica 数据流，影响较轻。  
  
  
02  
  
**全球影响范围广泛：**  
  
**数十亿用户暴露在隐蔽追踪之下**  
  
  
**网站部署情况**  
  
根据研究者对BuiltWith与HTTP Archive数据的分析，全球大约有580万网站嵌入了Meta Pixel，另有近300万个网站集成了Yandex Metrica。通过遍历前10万热门网站的爬虫测试，研究者发现：  
  
  
Meta Pixel在欧盟和美国站点中分别有15,677和17,223个在加载页面时主动尝试与本地端口通信，**即使用户未点击“同意Cookie”**  
，仍有11,890（EU）和13,468（US）个站点默认执行该操作。  
  
  
Yandex相关行为的触发频率略低，但在EU与US站点中仍达到了1,064和1,095个的“无同意通信”事件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5GCulQvNeNJ7uBQATIondnOk545rz2jbD4yhegicJb4icDWIV0toXqh3ID42xce1IZuf3fU1jFORLQ/640?wx_fmt=png&from=appmsg "")  
  
  
这说明，在用户毫不知情的情况下，大量主流网站已被用于实施这种“隐形跟踪”机制。  
  
  
**App责任缺位**  
  
报告指出，Meta 与 Yandex 均未在其公开文档或开发者资料中披露该跨端通信机制，许多网站接入者在发现本地监听行为后曾向 Meta 支持询问，但得到的仅是泛泛回应，未作明确说明。  
  
  
Meta 的跨端监听行为据推测始于 2023 年 9 月，已确认在 2025 年 6 月 3 日完全移除了相关代码，并称正在就政策解释问题与 Google 进行沟通。  
  
  
Yandex 的该机制则最早可追溯至 2017 年初，彼时即已通过 HTTP 请求与其 App 建立通信通道。Yandex 在回应中称“该机制仅用于改善 App 个性化推荐，不涉及敏感数据，也不会去标识用户身份”，但承诺将停止相关行为。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5GCulQvNeNJ7uBQATIondnBWSgD5pibvwkpGwZVJIN5iaOSLQN5AgfOia1Z6PbsT7jO5RQEmGhiadmuw/640?wx_fmt=png&from=appmsg "")  
  
  
尽管两家公司均表示已终止使用该机制，但这一“隐形通道”**长达 8 年**  
的存在周期与未披露使用意图，已足以引发全球对跨端追踪边界与系统隐私机制有效性的深层担忧。  
  
  
03  
  
**Android平台机制性缺陷**  
  
**首次遭到大规模“战术化利用”**  
  
  
研究人员指出，这种追踪方式最核心的问题在于**绕过了Android平台原有的沙箱隔离、权限控制、隐私提示与用户授权机制**  
，造成以下安全困境：  
  
  
  
**浏览器与App间数据壁垒失效：**  
  
Web 与 App 本应数据隔离，但通过 localhost 端口连接后，浏览器中的行为被“泄露”给后台应用。  
  
  
**现有隐私控制机制无效：**  
  
无痕模式、cookie 清除、广告ID重置、未登录状态等均无法阻止此类追踪。  
  
  
**平台政策与技术空白：**  
  
Google直到2025年5月才在Android Chrome中引入临时防护措施，目前尚未有全面系统性修复。  
  
  
值得注意的是，研究人员尚未在 iOS 平台发现同类行为，但指出由于 iOS 亦支持 WebKit 本地通信，在**技术上也并非不可实现**  
，未来或存变数。  
  
  
04  
  
**监管与治理：**  
  
**应对“本地通道滥用”刻不容缓**  
  
  
尽管 Meta 与 Yandex 在研究发布后宣布“停用相关功能”，但此次事件暴露出平台方与监管体系的多重盲区：  
  
  
  
**技术合规的灰色地带：**  
  
行为发生在本地设备之间，通信无出网，未被当前 cookie、隐私政策覆盖，合规监管亟需更新定义；  
  
  
**平台责任机制缺失：**  
  
App 开发者对 SDK 行为无感知，用户也无法察觉，厂商与平台需提供更加细致的权限说明与提示机制；  
  
  
**防御能力依赖单一浏览器厂商：**  
  
目前仅 Google 和 Brave 推出部分防护措施，其他 Chromium 浏览器与国产浏览器尚未覆盖。  
  
  
研究团队建议，未来需推动：  
  
  
- Android 系统加强本地通信访问权限控制；  
  
- 浏览器加强 localhost 通信透明化与用户提示机制；  
  
- 平台引入用户可控的“本地监听”权限项，并纳入隐私沙箱与广告ID治理框架中；  
  
- 对跨平台ID桥接行为建立行业合规评估体系，强化开发者与平台透明度责任。  
  
  
  
  
本次披露的研究表明，传统意义上的“App权限边界”与“浏览器隔离机制”正在被绕过，新一代的跨应用、跨平台用户追踪技术正在崛起。这一趋势挑战了当前隐私防护模型的边界，也对Android生态系统、浏览器厂商、网站运营者乃至监管机构提出了更高要求。  
  
  
在全球日益重视数据主权与平台透明的背景下，Meta与Yandex的案例为业界敲响了警钟：隐私保护不能仅依赖“用户设置”，更需平台、技术标准与监管措施的全面升级。  
  
  
消息来源：https://localmess.github.io/  
  
  
推荐阅读  
  
  
  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">01</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788650&amp;idx=1&amp;sn=c9d73ba425f3d008e84c74b2b2798664&amp;scene=21#wechat_redirect" textvalue="网络安全十大先进威胁检测技术" data-itemshowtype="0" linktype="text" data-linktype="2">网络安全十大先进威胁检测技术</a></span><span leaf=""><br/></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">02</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788643&amp;idx=1&amp;sn=d8e3e999b9ed0aab6deeed99ca60d127&amp;scene=21#wechat_redirect" textvalue="苹果硬刚欧盟" data-itemshowtype="0" linktype="text" data-linktype="2">苹果硬刚欧盟</a></span><span leaf=""><br/></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">03</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788658&amp;idx=1&amp;sn=8936527f221e8c0e16cce66cf99d5567&amp;scene=21#wechat_redirect" textvalue="Chrome插件硬编码API密钥泄露" data-itemshowtype="0" linktype="text" data-linktype="2">Chrome插件硬编码API密钥泄露</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5GCulQvNeNJ7uBQATIondnudcria1Bia63zSniafrfcyibJ4pvI41IBia4XSVf2z9libz2F3KeXibCRjSFg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb5GCulQvNeNJ7uBQATIondn2vr3rjnaaNAjhCthmxpN6klIPrkbzB99zKyuEsM3nVlkttWjdBIkYw/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
