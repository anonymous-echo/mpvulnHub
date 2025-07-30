#  外网露出：新版 CobaltStrike 顶级免杀套件Arsenal kit   
 棉花糖fans   2025-01-08 04:49  
  
##   
  
上周日，某TG频道公开发布了CS4.10-Arsenal Kit工具包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BgpLXnnTHwatqQhlrNFGzvHoJLDVuZwxtjdicKmregxnVyribV6OqbP4HYWeQZoURdiczn4yYK7GQGs3wMMdn7fhQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250108112122048  
  
经查，hash与官方一致：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BgpLXnnTHwatqQhlrNFGzvHoJLDVuZwxetzwnrA7XrrJ170J6Wkt0BFt0ibDiaOKn99mALuic2A7Z3RIt8jKib7RFQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250108112509202  
#### 以下为相关描述  
  
武器库套件是将各个独立套件组合成一个单一套件。构建此套件会生成一个单一的 Aggressor 脚本 dist/arsenal_kit.cna， 可以加载该脚本，而不需要单独加载各个套件。此套件由 arsenal_kit.config 文件控制， 该文件配置了使用 build_arsenal_kit.sh 脚本构建的套件。  
  
各个独立套件仍然可以单独使用。每个套件都有自己的 Aggressor 脚本文件，位于 dist/<套件名称>/<套件名称>.cna， 可以单独加载。有关详细信息，请参阅套件的自述文件。  
  
build_arsenal_kit.sh 脚本会根据 arsenal_kit.config 文件中启用的套件进行构建， 该脚本会为每个启用的套件执行 kits/<套件名称>/build.sh 脚本。要构建单个套件， 请进入 kits/<套件名称> 目录并执行 build.sh脚本。对于单个套件的 build.sh 脚本， 运行时不带参数可以查看帮助文本，以获取有关所需参数的更多信息。  
  
请注意，udrl-vs、mutator 和 postex 套件是独立的，必须单独构建。它们不包含在 arsenal_kit.config文件或 build_arsenal_kit.sh 脚本中。  
#### 套件及支持的 Cobalt Strike 版本  
  
<table><thead><tr><th style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;background-repeat: no-repeat;background-color: rgb(240, 240, 240);width: auto;height: auto;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">套件</th><th style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;background-repeat: no-repeat;background-color: rgb(240, 240, 240);width: auto;height: auto;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">Cobalt Strike 版本</th></tr></thead><tbody style="font-size: 14px;line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Artifact</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.x</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Sleepmask</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.7 及以上</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">UDRL</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.4 及以上</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">UDRL-VS</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.4 及以上</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Mimikatz (20220919)</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.5 及以上</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Postex</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.10 及以上</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Resource</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.x</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Process Inject</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.5 及以上</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Mutator</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">4.7 及以上</td></tr></tbody></table>  
- 不包含  
  
- Elevate 套件  
  
- applet  
  
- powerapplet  
  
适用于 4.4 版本的 Sleepmask 套件可在 https://download.cobaltstrike.com/scripts 下载适用于 4.5 和 4.6 版本的 Sleepmask 套件包含在 20230911 及更早版本的武器库套件中  
#### 套件文件和目录描述  
  
<table><thead><tr><th style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;background-repeat: no-repeat;background-color: rgb(240, 240, 240);width: auto;height: auto;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">位置</th><th style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;background-repeat: no-repeat;background-color: rgb(240, 240, 240);width: auto;height: auto;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">描述</th></tr></thead><tbody style="font-size: 14px;line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">arsenal_kit.config</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">武器库套件配置文件</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">build_arsenal_kit.sh</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">武器库套件构建脚本</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">templates/</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">Aggressor 脚本全局模板</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">templates/arsenal_kit.cna.template</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">武器库套件模板基础脚本</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">templates/helper_functions.template</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">辅助函数模板脚本</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">dist/</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">构建输出的默认位置</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">kits/</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">套件的源代码</td></tr><tr style="color: rgb(89, 89, 89);background: no-repeat rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">kits/&lt;套件名称&gt;/script_template.cna</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">套件的基础模板</td></tr></tbody></table>  
#### 要求  
  
此套件设计为在 Linux 平台上运行。已在基于 Debian 的 Linux 上进行了测试。  
  
您需要以下内容：  
- 最小 GNU Windows 交叉编译器 - apt-get install mingw-w64  
  
#### 快速开始  
1. 查看并编辑 arsenal_kit.config 文件，将包含的套件设置为 true  
  
1. 构建套件 build_arsenal_kit.sh  
  
1. 加载脚本 - 在 Cobalt Strike 中 -> 脚本管理器 -> 加载 dist/arsenal_kit.cna  
  
使用钩子的命令将在脚本控制台中显示输出。  
  
生成工件的示例（仅启用了工件套件）：  
```
[10:16:12] [arsenal_kit.cna] ######################################
[10:16:12] [arsenal_kit.cna] # Cobalt Strike 武器库套件
[10:16:12] [arsenal_kit.cna] # (c) 2012-2024 Fortra, LLC 及其集团公司。所有商标和注册商标均为其各自所有者的财产。
[10:16:12] [arsenal_kit.cna] ######################################
[10:16:12] [arsenal_kit.cna] 工件套件已加载
[10:16:25] [arsenal_kit.cna] 工件 - EXECUTABLE_ARTIFACT_GENERATOR 钩子
[10:16:25] [arsenal_kit.cna] 工件 - /home/arsenal-kit/dist/artifact/artifact64big.exe
[10:16:25] [arsenal_kit.cna] 工件 - 长度 265737

```  
#### 修改  
  
我们鼓励您对此代码进行修改，并在您的项目中使用这些修改。请勿重新分发此源代码。它不是开源的。它是作为对已授权 Cobalt Strike 用户的福利提供的。  
  
每个套件都有一个自述文件，详细说明了如何进行自定义。  
## 下载链接：  
  
  
公众号后台回复：  
**0108**  
  
  
## 往期文章：  
  
  
[自定义kali：增加60+常用渗透工具，哥斯拉特战版，cs魔改应有尽有，菜单栏启动2024-12-27](https://mp.weixin.qq.com/s?__biz=MzkyOTQzNjIwNw==&mid=2247491206&idx=1&sn=b7eaef72230be9c92c0e5a1dde5d0f66&scene=21#wechat_redirect)  
  
  
[交流群新增github poc监控机器人2024-12-29](https://mp.weixin.qq.com/s?__biz=MzkyOTQzNjIwNw==&mid=2247491222&idx=1&sn=e39e5a74e9431480b1582b2b79c317f7&scene=21#wechat_redirect)  
  
  
[年末最后一次打广告了，会员站年终抽奖，奖品总计5000元,此时就是最好的购买时机！](https://mp.weixin.qq.com/s?__biz=MzkyOTQzNjIwNw==&mid=2247491224&idx=1&sn=47968ba82b9e6bea17b2511da4faf5a7&scene=21#wechat_redirect)  
  
  
[2024-12-30](https://mp.weixin.qq.com/s?__biz=MzkyOTQzNjIwNw==&mid=2247491224&idx=1&sn=47968ba82b9e6bea17b2511da4faf5a7&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkyOTQzNjIwNw==&mid=2247491224&idx=1&sn=47968ba82b9e6bea17b2511da4faf5a7&scene=21#wechat_redirect)  
  
  
****  
  
