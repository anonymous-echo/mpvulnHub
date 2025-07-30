> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU3MDg2NDI4OA==&mid=2247491228&idx=1&sn=052a45b2108d847c0ec904a1c3075ce6

#  两载光阴，我与0day的两次匿名邂逅  
原创 private null  轩公子谈技术   2025-06-13 14:07  
  
凌晨三点的屏幕泛着冷光，代码像一串永无止境的咒语在眼前流淌。突然，控制台跳出的异常字符让我瞳孔骤缩 —— 那是两年前某个深夜，我第一次与 0day 相遇时，同样令人脊背发凉的信号。  
  
彼时的我尚不知晓，这个瞬间将成为一场隐秘冒险的起点。从迷雾重重的代码迷宫，到暗藏杀机的系统缝隙，两次跨越时空的 “匿名邂逅”，如同命运抛来的两枚谜题，裹挟着技术与人性的暗涌，在安全世界的角落里悄然发酵。而这一次，我决定剖开时间的褶皱，将那些未曾言说的故事，悉数摊开在你面前。  
  
当渗透 url 在键盘敲击声中生成，我深吸一口气将它输入浏览器。页面跳转的瞬间，惨白的登录框突兀地撞入视线，金属质感的 “登录” 按钮透着冷意，仿佛在无声嘲笑。输入框旁跳动的光标像倒计时的指针，我知道，真正的较量才刚刚开始 —— 那些藏在用户名与密码背后的，或许是坚不可摧的防线，也可能是通往深渊的钥匙。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdeibicLjIG3aRuBkIwWKuibeVtuwlsicAnpibbvhnrgloHAuRiaKOY0DCaRsg/640?wx_fmt=png "")  
  
   
  
目标系统牵系着关键命脉，每一行代码都必须铸造成密不透风的钢铁壁垒，不容任何脆弱的缺口  
  
反复深挖日志里 “熊猫头” 标记下的数据暗流，翻遍每一寸代码角落，却始终没捕捉到可疑路径的蛛丝马迹，诡异的平静反而让人后颈发凉  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdicWbquZEletPq2gnicjNFRIIMyh2iayxpUPcTicibMsJYJVHMTholBSianQQ/640?wx_fmt=png "")  
  
   
  
鼠标滚轮在页面上快速滑动，指尖几乎要把键盘磨出火星。右键点击 “查看源码” 的瞬间，密密麻麻的字符瀑布倾泻而下，我屏住呼吸逐行筛查，除了几行孤零零的 js 路径在黑暗中闪烁，再无任何可疑痕迹。就像在一座空荡的古堡里翻遍每块砖石，最终只找到几片褪色的旧信笺，真相依旧藏在更深的迷雾里。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdo55PNFKu965zqqJ3gyXYCIdKLqqIWx3ndpUuIEaZEwZGe6HGgbicrhw/640?wx_fmt=png "")  
  
   
  
凭借二十年挖掘编辑器的 “嗅觉”，我深知 static、plugin 这些看似寻常的路径，往往藏着最隐秘的线索。指尖在键盘上快速敲击，像在黑暗中摸索密码的盲人。  
  
当目光扫过js的瞬间，呼吸几乎停滞 —— 那熟悉的文件结构，如同暗夜中突然亮起的灯塔，终于让这场与编辑器的 “捉迷藏”，有了突破性的进展。敲击的键盘，如同旋律直至敲出/ueditor/index.html，那些蛰伏在代码深处的蛛丝马迹，正逐渐拼凑出系统背后的真实模样。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhd1PgnibPE5D3Q3AtToIenoMEoY0pD47eia7m4cmZckFSwt6GsWv5vJMPQ/640?wx_fmt=png "")  
  
   
  
指尖悬在键盘上方短暂停顿，屏幕幽光映出我紧锁的眉峰。深吸一口气后，一连串指令如子弹般倾泻而出，目录扫描工具开始疯狂吞吐字符。进度条跳动的节奏越来越快，像是黑暗中急速逼近的脚步声，每一次刷新都可能撕开系统的隐秘角落，也可能坠入更深的迷雾。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdJUUj6m5oVTDzNYlAlhdXauMHex3fZ81WHPfq3Xiav4F6NAj2hogUhAw/640?wx_fmt=png "")  
  
   
  
倒计时的光标仍在疯狂跳动，就在我几乎要被登录框的冷意吞噬时，页面右侧突然闪过一抹微弱的蓝光。鼠标下意识地划过去，“接口文档” 四个黑色小字像蛰伏的毒蛇，诡异地从密密麻麻的目录中探出头来。我几乎能听见自己剧烈的心跳声 —— 这蛰伏在系统暗处的 “致命手册”，究竟是打开宝库的钥匙，还是触发陷阱的机关？指尖触碰到鼠标的瞬间，仿佛按下了潘多拉魔盒的封印，一场更惊心动魄的博弈，已然拉开帷幕。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdPZSMx7JAuxP9GZvltb2iaTtraibemHF1G00XRGWzlxazzGAY32sWIW7w/640?wx_fmt=png "")  
  
   
  
手指在键盘上飞速舞动，wsdler插件如利剑出鞘般刺入代码深处。屏幕上的字符如同受惊的鱼群四散奔逃，转瞬便被解析成整齐排列的格式。我紧盯每一行输出，像极了考古学家凝视出土文物，不放过任何细微线索。  
  
挨个测试方法的过程漫长而压抑，直到某个接口返回的瞬间，屏幕突然炸开一片刺目的数据 —— 系统名称、版本号、部署架构…… 这些本该深埋的核心信息，如同被撬开的保险箱，赤裸裸地暴露在眼前。指尖无意识地摩挲着鼠标，后背却早已渗出冷汗，这场隐秘的攻防战，终于撕开了第一道缺口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdeGKOCFpibkXJjgPG5v67nRK23MGUQgJuxRYeK1jP3vvUd70sQSxia7sQ/640?wx_fmt=png "")  
  
   
  
键盘敲击声戛然而止，当 HTML 解码窗口跳出那串字符时，呼吸都跟着停滞。ftp密码：dss/dss，IP：127.0.0.1，这些信息像突然刺入黑暗的匕首，在屏幕上泛着冷冽的光。心跳声震得耳膜发疼，这看似普通的内网地址背后，究竟藏着怎样的玄机？  
  
手指不受控地悬在键盘上方，仿佛能触摸到数据流的震颤。“扫描公网 IP 的 21 端口！” 念头如闪电划过，我立刻调出扫描工具，进度条开始跳动的瞬间，就像点燃了导火索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdFyDj5vAE6uQn1NXoriaHYTnKclYJP88aBZa9TGH5ShQfDmB4FKmyBeA/640?wx_fmt=png "")  
  
   
  
扫描工具的进度条最终定格在 100%，刺眼的 “21 端口开放” 字样如同一记重锤砸在心头。我攥紧鼠标，迅速调出连接工具，指尖在键盘上敲出登录指令，每一个字符都像是通往宝藏的密码。然而，预想中的连接成功提示并未出现，取而代之的是冰冷的报错弹窗，仿佛一道无形的铁幕横亘在眼前。  
  
屏幕幽光下，报错信息不断闪烁，像极了对手无声的挑衅。明明端口已敞开缝隙，却又在最后一刻竖起铜墙铁壁。空气中弥漫着无形的火药味，我死死盯着那串 IP，后颈的寒意顺着脊椎攀爬  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdmFAscdLST5LqPZdFGpciawc68dUCjicGMJsq2kIHq2FsX6bKfAdHX1qw/640?wx_fmt=png "")  
  
   
  
冷汗浸透的后背逐渐发凉，盯着那道冰冷的连接屏障，我终于咬牙按下 Ctrl+W 关闭窗口 —— 这条路已然走到尽头。但目光扫过满屏杂乱的数据时，突然被一抹暗红的字符拽住视线：某个.action 后缀的链接，正像块带血的诱饵，在敏感信息堆里若隐若现。  
  
颤抖的手指悬在回车键上方三厘米处，犹豫不过半秒便重重按下。页面加载的转圈圈标像催命符般转动，直到 “未授权访问” 的警告框骤然弹出。屏幕白光刺得眼眶生疼，可嘴角却不受控地扬起 —— 这道禁令背后，藏着比开放端口更诱人的秘密，也意味着，这场攻防游戏，才真正进入白热化阶段。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdT4y4gHg0SNd8XUx6J9ETZ9Yn2OHjqqG9uWgY9ARmjibeYaw4OpRd6zg/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdpkDjL51BvicmsNjibicFtPRstMib32Lib6BtavXo3jdT51fCKLSIt7FIcPQ/640?wx_fmt=png "")  
  
   
  
“未授权” 的警告字样在屏幕上明明灭灭，突然，一抹像素模糊的头像框闯入视野 —— 这藏在权限壁垒后的上传入口，像黑暗中突然亮起的萤火虫，瞬间点燃所有神经。颤抖着将 jsp 文件拖进上传框，点击确认的刹那，心跳声几乎要震碎耳膜。  
  
然而页面只是短暂卡顿，随即恢复死寂，连一丝上传成功的提示都吝啬给予。疯狂刷新页面、翻查请求记录，终于在层层嵌套的响应头里揪出一个路径，可当鼠标点击的瞬间，浏览器却突然弹出下载框，仿佛有人在暗处按下机关，将这条珍贵的线索强行封存成冰冷的文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdbIemhdS00B1icibJXct5OWuKLXZ7IraY2fCGesxAFNoOLM2oXicRjEHcg/640?wx_fmt=png "")  
  
   
  
滚动鼠标滚轮的指尖突然僵住，nday 记录里鲜红的 “已修复” 字样刺得眼球生疼。那些曾寄托着突破希望的下载接口，此刻像被人猛然抽走的跳板，消失在系统更迭的浪潮里。方才还在脑海中勾勒的文件读取路线图，瞬间化作飘散的灰烬。  
  
屏幕蓝光映着我紧蹙的眉峰，修复日志的字符在眼前不断重影。这看似平静的 “已修复” 三个字，实则是对手竖起的新壁垒，无声宣告着：这场攻防战的棋局，又被推到了新的困局。但键盘缝隙里还残留着上次敲击的余温，我摩挲着鼠标，目光再次聚焦在跳动的光标上 —— 既然旧路已封，那就再辟一条通往真相的暗道。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdGKrZ2x3bOqD8yAq5xMjhfGY6kx6H5H0j6uE0w9umudjO6xUkYffjHQ/640?wx_fmt=png "")  
  
   
  
我死死盯着 “熊猫头” 标记下的数据，瞳孔随着屏幕滚动剧烈收缩。颤抖着点击链接，页面加载的进度条仿佛凝固了时间。直到 “未授权访问” 的提示框弹出来，带着刺目的红光。但我却忍不住笑出声，这道禁止的屏障背后，分明是通往系统腹地的暗门。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdQnJq16vMF8fbGic5Pk3nrcpXfy1I4a7UiaYiamkzx654hTiaoBMHoQqHTw/640?wx_fmt=png "")  
  
   
  
颤抖着在XML 中输入  
' or 1=1 --  
，呼吸在按下回车的瞬间凝滞。  
  
页面加载的进度条像心跳般缓慢跳动，当原本空白的界面突然跳出数据库表名时，我几乎要将鼠标捏碎。那些排列整齐的字段名，此刻成了最诱人的战利品。顺着注入点深挖，一步步绕过防护机制，权限等级数字在眼前不断攀升，直到 “管理员权限获取成功” 的提示弹出。屏幕幽光中，胜利的战栗混着冷汗爬上脊背，这场在代码迷宫中的生死博弈，终于撕开了第一道缺口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdAVicKcjdgZAkHdiavOia5Etok7tWcDhZeb73GlCzasSgxyxDqgH1skibbw/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdKb97UbkoSCJg8hyecwxIc1TVVuJbFuwWFC77iamwfxUzU9SJzjj3NyQ/640?wx_fmt=png "")  
  
   
  
上文采用 ai 优化，整体段落像流水席。  
  
   
  
码比较多，因为不得不码，但大家应该猜到了这个系统  
  
23 年 12 月份，也测过相同的系统，都是基于二开的。  
  
这个洞比较有意思，但是也很危险。  
  
同样的开局也是登陆框，然后是目录扫描存在配置目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdcDWxpAmWGE4sKeY3gYqB5eQviaicy9go4LlP9DrKt0XicRiavlia3b05j4A/640?wx_fmt=png "")  
  
   
  
直接访问 config 显示空白，所以要查看源代码，又第二次嵌入 js  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdzm952ZnFn0FUUkuXLT7oyV2SzDhzUJolrq9tPrLLuFQL3mCXAabLoQ/640?wx_fmt=png "")  
  
   
  
源码中存在system.js 文件，里面则是定义了系统的开机，关机，重启，tomcat 的开启，关闭，以及重启等 22 个 action。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhdAXUibo27EwiacSQia7ssDB5q01gvC7koF3BiaP2BWlcsOe0OsJj6GZPOZA/640?wx_fmt=png "")  
  
   
  
拼接路径，可对系统进行重启，关机  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhd6oygYepZPwUC6Rsy2Vicju9h5JYkv4icTwDWWJK3lDkxsOtFsz3xHlHQ/640?wx_fmt=png "")  
  
   
  
等待五分钟后 刷新页面，显示正常  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZTtBob83ibqFgtqatUia5lhd9zJTibictXq4icHDrtica2A1lIHdb1aibyRcFBCyOYG14TcfpBuQm81125Q/640?wx_fmt=png "")  
  
   
  
   
  
