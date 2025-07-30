#  开源代码漏洞扫描器 OSV-Scanner 新增修复和离线功能   
原创 SenderSu  wavecn   2025-01-03 00:14  
  
要防范软件供应链攻击，自动化扫描工具必不可少。OSV-Scanner 这个开源代码漏洞扫描器，以及支持该扫描器的漏洞数据库 osv.dev 在推出的当时就有点及时雨的意思。  
  
之前笔者对 OSV-Scanner 已经做了介绍和功能跟踪。最新版本（本文为1.9.2）增加了一些颇为有用的实验性功能，比如  
离线模式和  
指导性纠正，所以再来仔细看看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdlEdyGiatmlJk4c2TF1Vo4KF2zUQZa9p22oDI9vE7TNXibV6QWfibwRg4g/640?wx_fmt=jpeg&from=appmsg "")  
<table><tbody><tr style="outline: 0px;visibility: visible;"><td data-colwidth="124" width="124" valign="middle" align="right" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(255, 255, 255);visibility: visible;"><span style="font-size: 12px;"><span leaf="">笔者：</span></span></td><td data-colwidth="453" width="453" valign="middle" align="left" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(255, 255, 255);visibility: visible;"><p><span style="font-size: 12px;"><span leaf="">国际注册信息系统审计师（CISA）</span></span></p><p><span style="font-size: 12px;"><span leaf="">软考系统分析师</span></span></p><p><span style="font-size: 12px;"><span leaf="">软件工程硕士</span></span></p></td></tr></tbody></table>  
本篇5千余字。  
<table><tbody><tr><td data-colwidth="44" width="44" valign="top" style="word-break: break-all;background-color: rgb(231, 145, 0);border-color: rgb(221, 221, 221);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">一</span></strong></span></td><td data-colwidth="532" width="532" valign="top" style="word-break: break-all;background-color: rgb(61, 167, 66);border-color: rgb(221, 221, 221);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">首先看看新增的指导性纠正功能[1]</span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span></strong></span></td></tr></tbody></table>  
离线模式看名字都大约知道是什么了，所以先看指导性纠正（Guided Remediation）这个晦涩功能名字的细节。  
  
其实在笔者理解，  
这个实验性功能如此命名，是工具开发人员不想用户误以为可以无脑使用此功能。  
  
指导性纠正功能可以帮助开发人员简单、快速地修正扫描器发现的有漏洞的依赖项，而且可以批量修复。据介绍，该功能的设计要点包括：  
  
1）利用 deps.dev 分解软件项目的整个传递图，通过分析确定消除漏洞所需的最少更改；  
  
2）根据能修正的传递性漏洞的总数，排列出直接依赖升级的优先级；  
  
3）根据依赖深度、严重性和是否关心仅用于开发的依赖等筛选项排列出修正漏洞的优先级；  
  
4）修改软件包清单（manifest）和锁定文件（lockfile）从而修正漏洞；  
  
5）修正漏洞还区分两种不同策略：  
就地修正（in-place）或  
重新锁定（relocking），不同的策略具有不同的风险和回报比率。就地修正风险较少但可能不全面，重新锁定则风险较大但更全面。  
  
由于是实验性的新功能，现在仅支持 npm 生态的 package.json 清单和 package-lock.json 依赖锁定文件。  
<table><tbody><tr><td data-colwidth="577" width="577" valign="top" style="word-break: break-all;border-color: rgb(255, 255, 255);background-color: rgb(172, 57, 255);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">1、使用就地修正策略</span></strong></span></td></tr></tbody></table>  
其实颇为简单：  
  
```
osv-scanner fix --non-interactive --strategy=in-place -L 完整路径指向package-lock.json
```  
  
  
如上一条命令，就完成了对指定的依赖锁定文件中漏洞依赖项的升级修正。  
  
几个参数组合起来的意思是对依赖锁定文件执行非交互式的（--non-interactive）就地（--strategy=in-place）修正（fix）。  
  
所谓“就地修正”，是把依赖锁定文件中已知有漏洞的依赖项的版本替换为没有漏洞的版本，且会维护该依赖项现有的约束，因此风险较少，但可能会有些漏洞因约束冲突等原因而没有得到纠正。  
  
另外，从参数就可以知道，OSV-Scanner 还提供了交互式的操作。  
  
如果运行 OSV-Scanner 时不给出 --non-interactive 参数，就会启动文本的交互操作界面。  
  
OSV-Scanner 会在界面中给出其扫描发现的漏洞清单，用户可以在清单中选择进行修正的漏洞项，或者深入查看漏洞信息，判断漏洞能否就地解决。  
  
扫描器默认设置为修正约束范围内的所有漏洞项，用户也可以选择其中若干漏洞项单独修正。  
  
本文的第三部分是尝试通过交互过程完成纠正。  
<table><tbody><tr><td data-colwidth="577" width="577" valign="top" style="word-break: break-all;border-color: rgb(255, 255, 255);background-color: rgb(172, 57, 255);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">2、使用重新锁定策略</span></strong></span></td></tr></tbody></table>  
重新锁定策略是相对激进的。在执行 OSV-Scanner 时，通过 --strategy=relock 指定使用该策略，并增加指定package.json文件所在：  
  
```
osv-scanner fix --non-interactive --strategy=relock -M 完整路径指向package.json -L 完整路径指向package-lock.json
```  
  
  
重新锁定策略的工作方式是根据 manifest 文件对所有依赖项的完整关系图进行重新计算，越过依赖项之间的约束关系，对所有需要的包均尝试使用其最新的版本，从而获得最大程度的漏洞版本纠正结果。  
  
由于该操作很可能导致大幅度修改依赖关系图，最终产生的结果有可能是破坏性的，所以要先做好本地备份或把相关文件提交到代码仓库进行记录，以便进行后续可能需要的还原或回滚操作。  
  
具体地，在重新锁定操作中，package-lock.json 的生成过程是先删除现有的 package-lock.json 文件和 node_modules/ 目录，然后运行 npm install --package-lock-only。这会重新创建锁定文件，但不会安装 node_modules/ 依赖项。  
  
随后，用户自行运行 npm ci 命令，重新安装新版本的依赖项。  
  
用户也可通过 --relock-cmd 参数，使用参数指定的命令取代原来的 npm install 安装命令。  
  
重新锁定策略也可以在交互过程中使用。  
<table><tbody><tr><td data-colwidth="577" width="577" valign="top" style="word-break: break-all;border-color: rgb(255, 255, 255);background-color: rgb(172, 57, 255);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">3、交互界面的指引作用</span></strong></span></td></tr></tbody></table>  
除了通过命令行简单地执行全部依赖项的重新锁定之外，用户还可以通过交互界面实施分步修补，调整直接依赖项的版本约束条件，深入发掘和升级存在漏洞的依赖项。  
  
这就是功能命名为 Guided Remediation 的原因。  
  
当用户通过漏洞依赖项清单选择和应用个别漏洞项的升级修改后，依赖关系图会被重新计算，使得用户可以在之前的操作基础上继续进行其它筛选。  
  
要注意：补丁的排列次序是按照修复效果最大化从高到低排序，优先显示那些用最少的依赖更改解决最多漏洞的补丁，  
而不是优先解决高危漏洞！  
  
如此反复筛选和尝试，直到完成选择后，用户便可通过界面上的 Write 选项完成对依赖锁定文件的更新写入。  
  
交互界面的具体操作在本文第三部分介绍。  
<table><tbody><tr><td data-colwidth="577" width="577" valign="top" style="word-break: break-all;border-color: rgb(255, 255, 255);background-color: rgb(172, 57, 255);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">4、筛选参数</span></strong></span></td></tr></tbody></table>  
该功能还有一些参数，可以用于筛选需要处理的漏洞项，比如：  
  
1）最大依赖深度： --max-depth  
  
考虑漏洞依赖时的最大依赖深度限制。例如，--max-depth=1 只会考虑直接影响直接依赖项的漏洞，而 --max-depth=2 会考虑到直接依赖项的依赖项，依次类推。当设置 --max-depth=-1 时，会考虑所有依赖项，无论其深度如何。  
  
2）最小CVSS分数： --min-severity  
  
考虑漏洞的最小 CVSS 分数。例如，--min-severity=7.5 只会考虑 CVSS 分数为 7.5 及以上的漏洞。如果漏洞的 OSV 记录中没有 CVSS 分数，则该漏洞不会被排除，也就是对于未评分的通常是新发现的漏洞一律从严。  
  
3）排除开发版本： --ignore-dev  
  
是否排除仅在 devDependencies 中使用的依赖项中的漏洞。  
  
4）忽略的漏洞清单：--ignore-vulns=<comma-separated list of IDs>  
  
从考虑范围中排除的 OSV ID 的清单。  
  
5）专门考虑的漏洞清单：--vulns=<comma-separated list of IDs>:   
  
只有在满足了其他参数所设置的条件时才需要考虑的漏洞的 OSV ID 清单。  
要注意“只有...才...”这个关系。  
  
6）按排序应用补丁数量：--apply-top  
  
指定按排序应用的补丁数量。补丁的排序即交互模式显示的顺序。按官方介绍，此参数的使用情况是编写脚本以测试特定补丁。设置 --apply-top=-1 将应用所有可能的补丁，默认如此。  
<table><tbody><tr><td data-colwidth="44" width="44" valign="top" style="word-break: break-all;background-color: rgb(231, 145, 0);border-color: rgb(221, 221, 221);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">二</span></strong></span></td><td data-colwidth="532" width="532" valign="top" style="word-break: break-all;background-color: rgb(61, 167, 66);border-color: rgb(221, 221, 221);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">接下来看看新增的离线模式[2]</span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span></strong></span></td></tr></tbody></table>  
离线模式（Offline Mode）解决了需要实现封闭式开发环境时之前的 OSV-Scanner 没法用的问题，因为 OSV-Scanner 运行时要通过 osv.dev 网站提供的漏洞数据库 API 获取漏洞信息。  
  
所以现在就提供了离线模式。  
  
就如大家想象的，离线模式的使用方法就是下载数据库到本地，然后用参数指定使用......不不不，这是个实验性功能，没那么简单。  
  
按文档，首先要设置名为：  
  
```
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY
```  
  
  
的操作系统环境变量，指定离线数据库所在的位置。比如 Windows 环境：  
  
```
SET OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=C:\Users\用户名\.osv-scanner
```  
  
  
或者 Linux：  
  
```
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/home/用户名/.osv-scanner
```  
  
  
然后，把离线下载相关的两个参数附加到扫描过程上：  
  
```
osv-scanner scan --experimental-offline --experimental-download-offline-databases 扫描目标
```  
  
  
这就是官方文档[2]说得很含糊甚至容易误解的地方：  
  
对于本文使用的 osv-scanner 1.9.2 版本，下载离线数据库并不是一个独立的操作，而是需要在执行扫描时附带进行。  
  
当环境变量指定的目录下找不到符合离线数据库目录结构的离线数据时，osv-scanner 就会自动创建目录结构并下载离线数据库。如果该目录内已经存在离线数据库文件，就会判断其是否过期和更新离线数据库。  
  
笔者作为系统分析师，从产品功能设计的角度看，其实应该在现有的 scan 和 fix 之外再增加直接下载数据库的命令。所以这确实就是实验性质，比较简单粗暴。  
  
文档提及，如果用户没有设置该环境变量，OSV-Scanner 会按默认规则查找，比如在 Linux 环境，会依次查找：  
  
```
os.UserCacheDiros.TempDir
```  
  
  
但 Windows 的在哪，文档也没说。笔者实验后发现是默认为：   
  
```
C:\Users\用户名\AppData\Local\osv-scanner
```  
  
  
很显然，如果是个人使用，干脆就不管那个环境变量也可以了。  
  
离线数据库还可以通过浏览器直接下载或使用 gsutil 工具手工下载，但就需要自己创建符合要求的目录结构。详细可以参考 OSV-Scanner 官方文档。  
  
一旦已经下载了离线数据库，后续的扫描就不需要再带上 --experimental-download-offline-databases 参数，只给出 --experimental-offline 参数即可使用离线数据库，即：  
  
```
osv-scanner scan --experimental-offline 扫描目标
```  
  
  
<table><tbody><tr><td data-colwidth="44" width="44" valign="top" style="word-break: break-all;background-color: rgb(231, 145, 0);border-color: rgb(221, 221, 221);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">三</span></strong></span></td><td data-colwidth="532" width="532" valign="top" style="word-break: break-all;background-color: rgb(61, 167, 66);border-color: rgb(221, 221, 221);"><span style="color: rgb(255, 255, 255);"><strong><span leaf="">对这两项实验性功能进行试用</span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span></strong></span></td></tr></tbody></table>  
笔者之前下载了一份 zxcvbn 比较新的分支项目[3]的源代码，就对它试试。  
  
题外话，关于 zxcvbn，可以参考笔者之前的文章（笔者的文章都是可以往前引用的）：  
  
《[攻防演练在即：我自己的密码够强吗？](https://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247486132&idx=1&sn=04ffe3874afedd6048320696d85e0d86&scene=21#wechat_redirect)  
》  
  
用 OSV-Scanner 不带参数扫描，结果如下：  
  
```
D:\trichards57-zxcvbn>.\osv-scanner.exe scan .Scanning dir .Scanning D:\trichards57-zxcvbn/ at commit a7f952e48b50bf5fde5b4fd193a184bcb53bd227Scanned D:\trichards57-zxcvbn\package-lock.json file and found 703 packages╭─────────────────────────────────────┬──────┬───────────┬───────────────────────┬─────────┬───────────────────╮≈│ OSV URL                             │ CVSS │ ECOSYSTEM │ PACKAGE               │ VERSION │ SOURCE            │├─────────────────────────────────────┼──────┼───────────┼───────────────────────┼─────────┼───────────────────┤≈│ https://osv.dev/GHSA-67hx-6x53-jw92 │ 9.3  │ npm       │ @babel/traverse (dev) │ 7.18.2  │ package-lock.json ││ https://osv.dev/GHSA-grv7-fg5c-xmjg │ 7.5  │ npm       │ braces (dev)          │ 3.0.2   │ package-lock.json ││ https://osv.dev/GHSA-x9w5-v3q2-3rhw │ 7.5  │ npm       │ browserify-sign (dev) │ 4.2.1   │ package-lock.json ││ https://osv.dev/GHSA-3xgq-45jj-v275 │ 7.5  │ npm       │ cross-spawn (dev)     │ 7.0.3   │ package-lock.json ││ https://osv.dev/GHSA-434g-2637-qmqr │ 5.3  │ npm       │ elliptic (dev)        │ 6.5.4   │ package-lock.json ││ https://osv.dev/GHSA-49q7-c7j4-3p7m │ 5.3  │ npm       │ elliptic (dev)        │ 6.5.4   │ package-lock.json ││ https://osv.dev/GHSA-977x-g7h5-7qgw │ 5.3  │ npm       │ elliptic (dev)        │ 6.5.4   │ package-lock.json ││ https://osv.dev/GHSA-f7q4-pwc6-w24p │ 5.3  │ npm       │ elliptic (dev)        │ 6.5.4   │ package-lock.json ││ https://osv.dev/GHSA-fc9h-whq2-v747 │ 4.8  │ npm       │ elliptic (dev)        │ 6.5.4   │ package-lock.json ││ https://osv.dev/GHSA-9c47-m6qq-7p4h │ 7.1  │ npm       │ json5 (dev)           │ 1.0.1   │ package-lock.json ││ https://osv.dev/GHSA-9c47-m6qq-7p4h │ 7.1  │ npm       │ json5 (dev)           │ 2.2.1   │ package-lock.json ││ https://osv.dev/GHSA-952p-6rrq-rcjv │ 5.3  │ npm       │ micromatch (dev)      │ 4.0.5   │ package-lock.json ││ https://osv.dev/GHSA-p8p7-x288-28g6 │ 6.1  │ npm       │ request (dev)         │ 2.88.2  │ package-lock.json ││ https://osv.dev/GHSA-c2qf-rxjj-qqgw │ 7.5  │ npm       │ semver (dev)          │ 6.3.0   │ package-lock.json ││ https://osv.dev/GHSA-c2qf-rxjj-qqgw │ 7.5  │ npm       │ semver (dev)          │ 7.3.7   │ package-lock.json ││ https://osv.dev/GHSA-4wf5-vphf-c2xc │ 7.5  │ npm       │ terser (dev)          │ 3.17.0  │ package-lock.json ││ https://osv.dev/GHSA-72xf-g2v4-qvf3 │ 6.5  │ npm       │ tough-cookie (dev)    │ 2.5.0   │ package-lock.json ││ https://osv.dev/GHSA-j8xg-fqg3-53r7 │ 5.3  │ npm       │ word-wrap (dev)       │ 1.2.3   │ package-lock.json │╰─────────────────────────────────────┴──────┴───────────┴───────────────────────┴─────────┴───────────────────╯≈
```  
  
  
如果是离线扫描，则扫描结果表格之前的提示内容会有所不同，多了一行加载本地离线数据库的提示，期间数据库的离线下载过程透明而且下载迅速无感：  
  
```
D:\trichards57-zxcvbn>.\osv-scanner.exe scan --experimental-offline --experimental-download-offline-databases .Scanning dir .Scanned D:\trichards57-zxcvbn\package-lock.json file and found 703 packagesLoaded npm local db from C:\Users\Sender\AppData\Local/osv-scanner/npm/all.zip
```  
  
  
（此处省略扫描结果表格）  
  
扫描结果说明存在有漏洞的依赖项。  
  
接下来尝试修复。为了仔细看看修复功能，于是选择不带任何参数启动 fix 命令，从而进入文本交互模式：  
  
```
.\osv-scanner.exe fix --experimental-offline -L .\package-lock.json
```  
  
  
出现如下图1的扫描过程窗口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSd4IOUfB65Mv30wjvqplTVeaeUnGPicTBFAkjutJmUTqS6sddMpxeY7cg/640?wx_fmt=png&from=appmsg "")  
  
图1 扫描中  
  
完成扫描后，提示扫描结果如图2，发现18项漏洞，其中0项为直接依赖，18项可转移，18项仅开发。界面允许用户选择操作和筛选设置（详见前文）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdYsDiaNoVlvv9aV4XCKCCC1ZibVBwLGy62bPkmODIyvnK2VHAuUYdISoA/640?wx_fmt=png&from=appmsg "")  
  
图2 扫描结果及操作  
  
箭头键上移选中 18 vulnerabilities，然后按回车就可以转入18项漏洞的清单如图3和详细信息界面如图4进行详细观察。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdJCUIKILnfeqMQZDogxLqj6P55AwPCoLpRr7t3p4icmJ7gOyR3Csyklw/640?wx_fmt=png&from=appmsg "")  
  
图3 漏洞清单  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSd1M5PO8S6Mvt5crnOARtVedexLAZQ6CgaVkMTgCVdZ6VUzSSNfxh32g/640?wx_fmt=png&from=appmsg "")  
  
图4 漏洞详情  
  
值得一提的是文本界面支持宽屏，拉宽命令行窗口后，显示内容就会变成两个框，如图5：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdt7pTzMAvy5CrLAvLQFFBWV0ZmQElFamqbGldSc7NHXLa7hD1D3UvcA/640?wx_fmt=png&from=appmsg "")  
  
图5 双窗口模式  
  
右边的框是信息框，这样就很直观。但由于发文排版原因，下文都还是用单框截图。  
  
交互界面上的操作元素就不再多说。界面提示，可以通过修改7个依赖包而修复18个漏洞中的11个。  
  
另外还可以注意到界面提示，由于缺少 manifest 文件（启动修复时笔者没有通过 -M 参数给出 manifest 文件所在），所以修复策略不能选择重新锁定（re-lock）。  
  
不考虑什么，如图6选择 Modify lockfile in-place，然后一个回车键执行就地修正。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdbiaCb3iahLTtI30HwB3VmxjCuM2HVpbFpDynibtpefFha68oQJpGibBDdQ/640?wx_fmt=png&from=appmsg "")  
  
图6 选择就地修改操作  
  
程序转入 IN-PLACE 就地修正界面，如图7：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdicutBHiaGUX1zSYyObwFYvydMY0hhyT0xEibLFK87JjFdWexAFf7prItw/640?wx_fmt=png&from=appmsg "")  
  
图7 就地修正操作界面  
  
此时用箭头键上下移动，就可以进入包信息了解到修改的7个包对应修改了哪些漏洞，如图8：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdYDdOZJxXsEZEhxkcJJ2SLAOpHQM1drod0g8BMicF87bibJ10wfejrnYg/640?wx_fmt=png&from=appmsg "")  
  
图8 包及对应漏洞的清单  
  
以及剩下没有修正的7个漏洞的具体情况如图9：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdEWGbOy1OtibnxsjEYm5Se4LmOpqlBlCobftVicPKiaQqtUVg2B2tvFzQQ/640?wx_fmt=png&from=appmsg "")  
  
图9 未能修正的漏洞清单  
  
界面还允许用户细化选择要进行的修改，也就是7个可修正的包之中选择哪些执行，选择如图10、图11的操作：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSd3GFvuGfQEcHDLSv39Ve9JQQeOVWjgrOzmlkpylqyhQ0umWXNF7pQZw/640?wx_fmt=png&from=appmsg "")  
  
图10 两项操作之选择应用的修正  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdtSFLRlSgIXz26syctvtHxbUXJlBDazz95Fu4hcshicelLI0pgq81qWg/640?wx_fmt=png&from=appmsg "")  
  
图11 选择需要应用的修补  
  
文本的交互式界面做成这样还是很不错了。  
  
返回到 IN-PLACE 操作界面，选择写入7项修改到锁定文件，如图12：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdz2Fsw5pgtc5SUZUtULCevicrxTw2CQWvnYQ5RXhozM0xSiakl5jlMlmg/640?wx_fmt=png&from=appmsg "")  
  
图12 两项操作之写入到锁定文件  
  
没有什么提示就完成了，界面显示剩余0个包可修改，如图13：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSdCUX7BRANaBzYRjo07eGXzuNVEibAECzwvQSX5DU96iauOmPygwqqxkbQ/640?wx_fmt=png&from=appmsg "")  
  
图13 完成写入剩余0个包可修正  
  
最后退出界面，指导性纠正过程就完成了。  
  
在执行前笔者已经备份了 package-lock.json 文件，于是祭出笔者最喜欢的代码比较工具 WinMerge 来比较一下修改前后，如图14：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HSHUiabvXVfO7c5kwJicHfgT7wXKXRNGSd2LVtX4R9ZtDpqyKLj2U3nzeegODMz9bMialXVJ8XFmJlyFkyfOmkyXw/640?wx_fmt=png&from=appmsg "")  
  
图14 修正前后的锁定文件比较  
  
最后补充一下，写入操作有可能出现可以理解的失败：  
  
```
Get "https://registry.npmjs.org/semver/6.3.1": net/http: TLS handshake timeout
```  
  
  
懂的都懂。笔者也不啰嗦。  
  
总之，笔者认为指导性纠正功能是相当有发展潜力的。  
  
~完~  
  
注：题头图为笔者自行拍摄。  
  
  
参考引用：  
  
[1] Guided Remediation | OSV-Scanner  
  
https://google.github.io/osv-scanner/experimental/guided-remediation/  
  
[2] Offline Mode | OSV-Scanner  
  
https://google.github.io/osv-scanner/experimental/offline-mode/  
  
[3] GitHub - trichards57/zxcvbn: Low-Budget Password Strength Estimation  
  
https://github.com/trichards57/zxcvbn.git  
  
  
**点赞和转发都是免费的**  
↓   
  
  
  
  
  
  
还可以看看这些内容：  
  
[OSV-Scanner 1.3.6 新功能：扫描归集软件包的开源许可证](https://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247486058&idx=1&sn=c7107e1ed2b413ecb084df42b58d477f&scene=21#wechat_redirect)  
  
  
[Git提交钩子触发 OSV-Scanner 漏洞扫描](https://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247485616&idx=1&sn=c62e61f9e1867f5466558d7d2b8f82b0&scene=21#wechat_redirect)  
  
  
[开源漏洞扫描器 OSV-Scanner 1.3 的新进展](https://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247485490&idx=1&sn=271b81f6fa536c60b9ea8eac637d4e54&scene=21#wechat_redirect)  
  
  
[OSV-Scanner: Google 研发的开源漏洞扫描器](https://mp.weixin.qq.com/s?__biz=Mzg4Njc0Mjc3NQ==&mid=2247484666&idx=1&sn=c623b5fa38938954abc6daa6ef1af992&scene=21#wechat_redirect)  
  
  
