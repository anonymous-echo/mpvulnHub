#  网络渗透“大杀器”：Cobalt Strike实操全揭秘   
原创 sky  泷羽Sec-sky   2025-01-14 16:32  
  
# 免责声明：  
  
该文章所涉及到的安全工具和技术仅做分享和技术交流学习使用，使用时应当遵守国家法律，做一位合格的白帽专家。  
  
使用本工具的用户需要自行承担任何风险和不确定因素，如有人利用工具做任何后果均由使用者承担，本人及文章作者还有泷羽sec团队不承担任何责任  
  
如本文章侵权，请联系作者删除  
# 一、开篇：探秘 Cobalt Strike 的隐秘天地  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKpd2crOKYOLQibiaHkRazHXUjgorATwibxbf49hS1AtmU53c41RrKt8ynw/640?wx_fmt=png&from=appmsg "")  
  
近些年来，网络安全事故频发，如同一场不见硝烟的鏖战，时刻挑动着人们紧绷的神经。不知大家是否还对某大型跨国企业惨遭黑客袭击、大量机密资料泄露，进而承受巨额损失的事件记忆犹新；还有部分政府机构网络系统被不法侵入，致使国家安全遭受严峻挑战。在这些扣人心弦的网络攻防对抗背后，有一款神秘且强悍的工具常常扮演关键要角，它便是 Cobalt Strike。  
  
Cobalt Strike，于网络安全领域堪称 “神器”，是众多黑客与安全专家的得力助手。其功能丰富多元，覆盖从渗透测试到模拟真实攻击场景的诸多范畴，仿若一把万能钥匙，能够突破网络安全防御的重重关卡。不管是在红队行动里模拟高级持续性威胁（APT），还是助力企业评测自身网络的安全防护水准，Cobalt Strike 皆展现出非凡实力。今日，就让我们一同揭开它神秘的面纱，深度探寻这款工具的实操诀窍。但请务必牢记，我们的探索仅限合法合规的学习与钻研，切莫逾越法律红线！  
# 二、工具初印象：Cobalt Strike 究竟为何物？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKzC5vEjbdJDxXnqeiczcBLhJPso69n40ClgFK3cia1w3gs1jLibWMrQBqg/640?wx_fmt=png&from=appmsg "")  
  
Cobalt Strike 可是网络安全领域声名远扬的一款工具，由美国的 Raphael Mudge 研发，属于专业的渗透测试与红队操作工具。简单来讲，它仿若一座功能超强的 “网络武器库”，专为安全专家定制，用以模拟真实攻击场景，协助企业与组织挖掘自身网络防御的漏洞。  
  
它的功能异常强大，涵盖社交工程、恶意软件传播、漏洞利用、远程控制、数据收集以及横向渗透等多个层面。不管是复杂的高级持续性威胁（APT），还是常见的网络渗透测试，Cobalt Strike 都能从容应对。  
  
例如，它支持 Spear Phishing（鱼叉式网络钓鱼）攻击，凭借精心炮制的钓鱼邮件，诱使目标用户点击恶意链接或下载附件，从而神不知鬼不觉地潜入目标网络；还可施展水坑攻击，在目标频繁访问的网站植入恶意代码，静候用户上钩。并且，它的协作功能极为灵活，多位渗透测试人员能够同步使用，共享资源、交流成果，大幅提升工作效率。此外，它还能与 Metasploit Framework 集成，如同为战士配备更为锐利的武器，进一步强化攻击能力。  
  
不过，大家千万要铭记，Cobalt Strike 虽强大无比，但却是一把双刃剑，必须在合法合规、获取授权的情形下运用，倘若私自滥用，必将触犯法律红线，后果不堪设想！  
# 三、实操前准备：构筑你的 “作战” 根基  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKodg1yOribDBAHxCZjROpyz2SXznZiaRkbykiacibnDaBcDRdcZtWURU7ww/640?wx_fmt=png&from=appmsg "")  
## （一）硬件与系统需求  
  
在正式上手 Cobalt Strike 之前，得先搭建好 “作战” 环境。这就如同战前筹备武器弹药、选定战场一般，适配的硬件与系统是顺畅使用 Cobalt Strike 的前提。  
  
先说硬件配置，虽说 Cobalt Strike 对硬件要求不算严苛，但也不能太过简陋。处理器起码得 2 GHz 及以上，如此才能保障工具运行流畅，避免卡顿到令人抓狂；内存至少要有 2 GB，要是内存不足，运行期间极易出现死机或反应迟缓的状况；磁盘空间也需预留 500MB 以上，毕竟工具自身以及后续操作生成的数据都得有存放之处。倘若使用 Amazon EC2 这类云服务，建议挑选至少 High-CPU Medium（c1.medium，1.7 GB）实例，为你的 “作战” 给予更稳固的支撑。  
  
再谈谈操作系统，Cobalt Strike 的服务端对系统颇为挑剔，当前仅支持 Kali Linux 2018.4 - AMD64、Ubuntu Linux 16.04、18.04 - x86_64 这些版本。而客户端相对宽松些，Windows 7 及以上、MacOS X 10.13 及更高版本、Kali Linux 2018.4 - AMD64、Ubuntu Linux 16.04、18.04 - x86_64 均可运行。拿 Kali Linux 来说，它自带诸多网络安全工具，与 Cobalt Strike 搭配堪称 “黄金搭档”，能让渗透测试如虎添翼。要是习惯用 Windows 系统，Windows 10 的兼容性也相当不错，操作界面友好，对新手比较亲和。  
## （二）软件安装与配置  
  
明晰环境的硬件和系统要求后，接下来便是安装与配置软件，这可是关键环节，容不得半点马虎！  
  
先看 JDK（Java Development Kit）的安装，由于 Cobalt Strike 由 Java 编写，所以 JDK 如同它的 “引擎”，没有 JDK，Cobalt Strike 便无法运行。以 Kali Linux 为例，安装 JDK 极为简便，开启终端，输入以下指令：  
  
这两条指令仿若向系统下达命令，使其自动帮我们把 OpenJDK 11 安装妥当，省心省力。安装完成后，输入 “java -version”，若能呈现 Java 的版本信息，便表明安装成功，如下所示：  
  
JDK 安装完毕，即可着手安装 Cobalt Strike 。先前往官网下载安装包，留意要依据自身系统选取对应的版本，千万别选错。下载完成后，解压安装包，若在 Linux 系统下，运用 “tar -zxvf” 指令即可，如下： 解压之后，进入解压后的目录，会看到若干文件与文件夹，其中 “teamserver” 即为服务端程序，“cobaltstrike.jar” 或者 “cobaltstrike” 便是客户端程序。  
  
接着，启动服务端。进入 Cobalt Strike 目录，使用指令 “chmod +x teamserver” 为服务端脚本赋予执行权限，而后执行 “./teamserver [IP 地址] [密码]”，此处的 IP 地址即为你服务器的 IP，密码要设置得繁杂些，以防被他人轻易破解，毕竟安全需从一开始就予以重视。如下：  
  
服务端启动成功后，再启动客户端。若在 Linux 系统下，执行 “./cobaltstrike” 或者 “java -XX:+AggressiveHeap -XX:+UseParallelGC -jar cobaltstrike.jar”；要是在 Windows 系统下，直接双击 “cobaltstrike.exe” 就行。客户端启动后，会弹出连接对话框，在 “host” 字段输入服务端的 IP 地址，端口默认是 50050，通常无需更改，“user” 字段填你的用户名，自定义即可，“password” 字段输入先前设置的服务端密码，点击 “Connect”，便能连接到服务端，是不是感觉距离实战愈发接近了呢？  
  
至此，我们的 “作战” 环境搭建完成，接下来便可开启 Cobalt Strike 的奇妙探索之旅！但再次提醒诸位，务必在合法合规、获取授权的前提下使用，千万别触犯法律红线。  
# 四、实战演练：开启渗透测试的征程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKqU0vcTc4ibHfxVqkkKibxYLekMHlY9vfybic6S8oPzBcP9OvJjntyPWFA/640?wx_fmt=png&from=appmsg "")  
## （一）启动 Cobalt Strike 服务端  
  
万事俱备，正式开启实战演练！首先要启动 Cobalt Strike 服务端，此乃整个操作的 “指挥中枢”。在终端输入启动指令，仿若向工具下达 “出征” 命令。以 Kali Linux 系统为例，指令一般是 “./teamserver [IP 地址] [密码]”，这里的 IP 地址必须精准无误，要是填错，客户端可就寻觅不到 “指挥部” 了；密码要设置得复杂又易记，诸如包含大小写字母、数字、特殊字符的组合，像 “Abc@123456”，千万别设置得过于简单，不然被黑客盯上，你的 “阵地” 可就危在旦夕。启动服务端后，能看到一连串的日志信息，它仿若 “作战日志”，记录着服务端的运行状态，倘若见到 “Server started on [IP 地址]:50050”，便意味着服务端启动成功，已然严阵以待！  
## （二）客户端连接  
  
服务端启动完毕，接下来便是客户端连接。打开客户端程序，会弹出连接对话框，这便是通往 “指挥部” 的大门。在 “host” 字段输入服务端的 IP 地址，端口默认是 50050，一般情形下无需变动，它仿若 “指挥部” 的固定通讯频道；“user” 字段填你的用户名，自定义一个即可，便于在团队协作中区分彼此；“password” 字段输入之前设置的服务端密码，这可是进入 “指挥部” 的 “钥匙”，绝对不能出错。输入完成后，点击 “Connect”，倘若顺利，就能连接到服务端，客户端界面会展示一些基本信息，诸如已连接的服务器 IP、你的用户名等，仿若收到 “指挥部” 的欢迎信号，是不是有点小激动呢？  
## （三）配置监听器：搭建信息 “通途”  
  
连接成功后，就得搭建一座信息 “通途”—— 配置监听器。监听器究竟是什么呢？简单来讲，它仿若一个 “情报收集站”，负责接收目标主机传回的各类数据，是后续操作的关键一环。  
  
在 Cobalt Strike 客户端界面，点击上方的 “Cobalt Strike” 选项，于下拉框中选择 “listeners”，接着在下方弹出区域点击 “add”，便进入监听器配置页面。此处有诸多参数需设置，首先是 “name”，给监听器取个响亮又易记的名号，例如 “HTTP 监听器”，方便后续辨识；而后是 “payload”，这可是重中之重，它决定了数据传输的方式，常见的有 HTTP、HTTPS 等协议。倘若目标网络环境对安全性要求不高，HTTP 协议便已足够，它简洁直接，数据传输效率高；要是目标较为警觉，那 HTTPS 协议更为适宜，它能加密数据，隐蔽性更强，仿若给情报传递披上 “隐身衣”。再将 “host” 设置为服务端 IP 地址，这是数据回传的目的地； “port” 自定义一个端口，注意别和其他常用端口冲突，比如设成 8888，这个端口仿若 “情报收集站” 的专属入口，静候目标主机的数据流入。 设置完成后，点击 “save”，监听器便配置就绪，它已然在后台悄然 “待命”，准备接收来自目标的 “情报”。  
## （四）生成木马：精心炮制你的 “诱饵”  
  
有了监听器，接下来便是制作 “诱饵”—— 生成木马。这一步务必小心谨慎，仿若制作精密暗器，稍有差池便可能被目标察觉。  
  
点击 “Attacks” 菜单，选择 “Packages”，再点击 “Windows Executable”，便进入木马生成流程。在此，我们能够选择不同类型的木马，常见的有 exe、dll、Office 宏病毒等。exe 木马仿若伪装成普通程序的 “间谍”，一旦在目标主机上运行，便能悄无声息地建立连接；dll 木马则更为隐蔽，它可注入到其他正常进程中，隐匿自身行踪；Office 宏病毒利用人们对办公文档的信任，潜藏在看似无害的 Word、Excel 文档里，当用户打开文档时，它便趁机发难。 选定木马类型后，关联之前配置的监听器，这一步极为关键，仿若给 “诱饵” 装上 “信号发射器”，让它知晓将收集到的信息往何处传递。配置好木马生成的路径，点击 “generate”，木马便生成了，是不是感觉自己仿若一位神秘的 “武器制造师” 呢？不过，千万要牢记，这些木马仅能用于合法的渗透测试，要是用于作恶，法律绝不姑息！  
## （五）权限提升与命令执行：掌控目标主机  
  
木马成功植入目标主机后，我们便迈出关键一步，不过此时权限或许还较低，仿若刚踏入敌方阵地的小侦察兵，诸多区域难以涉足。因而，接下来要做的便是权限提升，让自己成为 “指挥官”，掌控全局。  
  
Cobalt Strike 提供多种权限提升手段，比如利用自带插件，它们仿若一些 “秘密武器”，能巧妙突破目标系统的防线；还可借助系统漏洞，这就要求我们对目标系统深入了解，找到其 “弱点”。当权限提升成功，我们便能如同操控自家电脑一般，执行各类系统命令，获取目标主机的信息，诸如查看文件目录、获取用户账号密码等。在客户端界面的命令输入框输入 “shell dir”，便能查看目标主机的文件目录，仿若打开目标主机的 “文件柜”，里面的文件尽收眼底；输入 “shell whoami”，可查看当前用户权限，确认自己是否已然成为 “指挥官”。还能操控目标主机，上传、下载文件，仿若拥有远程的 “文件传输助手”，是不是超级酷炫？  
  
经由这一系列操作，我们便完成一次简易的 Cobalt Strike 实战演练，是不是感觉网络安全的世界既神秘又刺激呢？不过，再度强调，务必在合法合规、获取授权的情形下使用，千万别触犯法律红线，让我们运用所学知识守护网络安全吧！  
# 五、进阶技巧：让你的渗透更为 “流畅”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKibQAvgQKlk0gqp7g8B2PZkZ25q3AwdXNBiaHRm20qqRPZfwlEuQtVicOA/640?wx_fmt=png&from=appmsg "")  
## （一）插件加载：拓展工具边界  
  
在掌握 Cobalt Strike 的基本操作后，我们便可借助加载插件进一步拓展其 “超能力”！插件仿若给汽车换上高性能部件，能让 Cobalt Strike 跑得更快、更远、更稳。 优质插件的来源广泛，其中 Github 堪称 “宝藏仓库”。在 Github 上，众多开发者分享自己精心打造的 Cobalt Strike 插件，涵盖各类功能，从提权辅助到信息收集增强，一应俱全。例如，有些插件专注于破解特定系统的密码哈希，运用先进算法与漏洞利用技术，能在短时间内获取密码明文；还有些插件可对目标网络展开深度扫描，发现隐匿在角落的设备与服务，仿若给网络环境做全方位的 “X 光透视”。  
  
加载插件的操作并不复杂，以常见的 cna 格式插件为例，在 Cobalt Strike 客户端中，点击 “Cobalt Strike” 菜单，选择 “Script Manager”，进入脚本管理器界面，这里仿若插件的 “候机大厅”，等待被启用。接着点击 “Load” 按钮，找到下载好的 cna 插件文件，选中并打开，插件便开始加载。加载完成后，你会发觉界面新增一些功能选项，或者在执行某些操作时，效率显著提升。像 “巨龙拉冬” 插件，它能提供自定义攻击载荷，让你在渗透时更具针对性；“LSTR” 插件则在大规模目标侦察方面表现卓越，能快速收集目标网络的详尽信息，为后续攻击策略的制定提供有力支撑，是不是感觉开启一扇通往新世界的大门呢？  
## （二）信息收集与分析：挖掘隐匿瑰宝  
  
在渗透测试进程中，信息收集与分析堪称重中之重，它仿若在黑暗中摸索时的 “手电筒”，能助力我们照亮前行之路，找到目标网络的弱点。  
  
Cobalt Strike 提供丰富的信息收集功能，让我们能从多个角度 “窥探” 目标网络。例如，利用其内置的端口扫描功能，我们仿若经验老到的水手在大海探测暗礁一般，找出目标网络中开放的端口，了解哪些服务正在运行，是 HTTP 服务、SSH 服务，还是其他关键业务服务。一旦发现开放端口，便能进一步探究这些服务是否存在已知漏洞，为后续攻击做好铺垫。  
  
再谈谈凭证收集，这可是个 “敏感活儿”。Cobalt Strike 能够通过一些巧妙手段，比如利用系统漏洞获取管理员权限后，搜索存储在目标主机上的各类凭证信息，像是浏览器保存的登录密码、Windows 系统的 SAM 文件中的用户哈希等。这些凭证仿若一把把钥匙，或许能开启通往更高权限或其他重要资源的大门。  
  
还有文件收集功能同样不容小觑。它能协助我们在目标网络中搜寻那些隐藏 “秘密” 的敏感文件，诸如配置文件、数据库备份文件等。想象一下，找到目标数据库的备份文件，那不就等同于觅得宝藏地图，里面或许包含用户数据、业务数据等关键信息，对了解目标网络的架构与数据存储方式大有裨益。  
  
收集到这些信息后，分析环节至关重要。我们可借助一些工具，比如数据可视化软件，将收集到的网络拓扑信息直观呈现，清晰洞悉各个设备、服务器之间的连接关系，仿若看到一幅完整的军事地图，何处是要害部位，何处是薄弱环节，一目了然。通过对凭证和文件的分析，我们能够进一步挖掘目标网络的潜在漏洞，制定更为精准的攻击策略，让渗透测试更高效、有力，真正成为网络安全领域的 “高手”！  
# 六、安全警示：合法运用，捍卫网络防线  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKFACDOaq3ar6ibcFpL03qrK9OS4zIbrCTQ8eONWWjJB3ItoPeqCNUBiaQ/640?wx_fmt=png&from=appmsg "")  
  
在深度探寻 Cobalt Strike 的强大功能后，我们必须严肃强调一个关键问题：合法使用。Cobalt Strike 作为一款功能卓越的渗透测试工具，仿若一把锋利的手术刀，在专业医生手中能救死扶伤，可一旦落入不法之徒手里，便会沦为伤人凶器。  
  
在现实世界中，因非法使用类似工具引发的严重后果数不胜数。曾有一伙黑客，私自运用 Cobalt Strike 对多家知名企业发动攻击，窃取商业机密，给企业造成难以估量的经济损失，致使股价暴跌、员工失业，整个产业链都受波及；还有不法分子，用它侵入政府部门网络系统，窃取敏感信息，严重威胁国家安全与社会稳定，最终这些人都受到法律严惩，面临漫长的牢狱之灾。  
  
依据我国《刑法》规定，非法侵入计算机信息系统罪、非法获取计算机信息系统数据罪等，都对这类行为予以明确约束。未经授权使用 Cobalt Strike 等工具进行渗透测试、攻击他人网络系统，便是在触碰法律红线。一旦查实，不但要承担高额经济赔偿，还可能面临数年乃至数十年的有期徒刑，人生从此蒙上阴霾，家人朋友亦会受牵连。  
  
我们学习与了解 Cobalt Strike，旨在提升网络安全防护意识，强化防御能力，助力企业与组织筑牢网络防线。在实际操作中，务必确保获取合法授权，遵循严格测试流程，在可控环境下演练。让我们携手并肩，在合法合规的轨道上，运用所学网络安全知识，守护网络世界的一方净土，为数字化时代的蓬勃发展保驾护航！  
# 七、结语：回顾与展望  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2en0jEfkgj1hr2aAfzxeKgKb9iaxnZXFnZGPCrYEAqXDyYcmo32h3ziaE9AF4X7icWiaaWDZh3ib8Bib2mQ/640?wx_fmt=png&from=appmsg "")  
  
至此，我们对 Cobalt Strike 的实操之旅暂且告一段落！经由这一番深度探索，我们知晓其强大功能，从搭建环境、实战演练，到进阶技巧运用，再到深刻领悟合法使用的重要性，每一步都充满挑战与惊喜。  
  
Cobalt Strike 仿若一把精密手术刀，在合法合规的使用者手中，它能精准剖析网络系统，揪出隐匿的安全隐患，助力企业与组织提前筑牢防线；可要是落入不法分子之手，就会变成伤人凶器，给社会带来极大危害。故而，我们务必时刻牢记合法使用原则，将所学  
## OSCP以及帮会  
  
**在boss直聘搜索oscp，cisp进行对比**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2elE97hyvL75ljKYHfUKN9JL94reibDPibRibVwUdMK07RNknmaDhHlJFkmKoxLz3jvfEMicxqD6fScvg/640?wx_fmt=png&from=appmsg "")  
  
  
今年就这一次机会，过年趁着别人都在娱乐的时候，趁此机会弯道超车。让基友对你的飞速进步发出惊叹，让曾经的同事对你的专业素养投来羡慕的目光。在你还在犹豫是否要报名OSCP的时候，别人已经行动了，在学习完oscp培训和泷羽sec的红队全栈课后，去考OSCP拿下竞争力，别人月入过几万了而你却还在为没有能力证明和没有工作而发愁，那为什么不行动起来呢?  
4000的价格比外面培训低了一半多，在加活动更低，也就这一次机会，后面都不会有了，就明年的这个时候才考虑举办  
  
oscp课程日常惊喜：   
  
1、报名一次oscp  
培训即可无限学习下一期，下下一期，学到你会再去考试oscp   
  
2、学生党想找工作的或者上班的想换工作的  
学完oscp可以找泷羽sec推荐（自己有技术实力就行）   
  
3、  
4000培训费用证明学生，可以分期，无利息，还优惠500   
  
4、拥有CISSP、OSCP、OSEP等多项专家认证的在职高级红队泷老师的就业方向指导 5、感兴趣的师傅们可以先找我咨询，  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ib2uY1nNcr75UZdJxeiafPex84h25dibUB3yJnzPQsfpR5ib1mnGQNH0d5w/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 帮会  
  
如果你喜欢水报告，这里有1000多份的src报告，供你学习思路  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ibX1yibwV2ichk3na8HzrqbNibSxbTa95TWQwk30D8ugwvibZv43ic2PCu1icQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ibk2mtQ7Iicggom6Q3UEBjh8KjHoeBqicEICWk8tX05fZkT2FcHtGN1ueg/640?wx_fmt=png&from=appmsg "")  
  
如果你想要一些源码，这里将有上百套的源码，供你魔改开发属于你自己的软件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ibufP8vCFU0YJFBrhDJaj8JQ1I2gzd0lB2B0EyzrtVcEIpYhskmGTDsQ/640?wx_fmt=png&from=appmsg "")  
  
如果你需要ppt，那么这里几千份ppt模板，供你选择，搭配上GPT，轻松搞定你的每月汇总  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ib72wdep8R674ZYC3paPmEfCeQDI5saYjZo8d9ESS9uVdUqSh1siaYetA/640?wx_fmt=png&from=appmsg "")  
  
如果你想要做副业，那么这里有几百个网赚项目，让你利用流量变现，每个月可以多几条烟钱（我不抽烟），每年也可以小赚1w+  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ib1xMpARNlgr86gqXLxdvz6ZNRtcmfKe2xGRw4QwzYaSmdJBPFOfJ2JA/640?wx_fmt=png&from=appmsg "")  
  
如果你想要各种破解工具，薅  
羊毛，不想开会员，那么这里是你最好的选择，还有很多的实用小工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ibWyb4KDEzp5Kk0sQS9Clr0fzibuicfT9AHjFI5tqC4aPTkPg8nvg2Q5ww/640?wx_fmt=png&from=appmsg "")  
  
还有各种的学习资料，包括且不限于渗透测试，python/c++编程，免杀，AI人工智障，逆向，安全开发等互联网资源（如果进了帮会需要百度网盘还请联系我）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ib5al6QicBq6dbmmuibtc1ib7DVOhYE8mfgmEdibxtBKJMWLlibia5GoElibriag/640?wx_fmt=png&from=appmsg "")  
  
  
如果你想要兼职，那么泷羽Sec提供了一个很好的兼职机会，您邀请一个人进入泷羽Sec帮会，凡是进入本帮会，嘉宾享72%的帮会推广收益，也就是【一次性付费金额  
0.72】，普通成员享受推广收益的40%也就是【一次性付费金额  
0.40】  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ibcXrGtVtJcKMH3axljnf6W7YcQomTic4G1txA7V7YyIumdZ2dEr4nf7Q/640?wx_fmt=png&from=appmsg "")  
  
泷羽Sec资料库，现一次性付费99，即可永久进入，加入泷羽Sec帮会，享受各种IT资源，资源持续更新中  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/CZHFycVsk2d4J7P0cjrc3iaOduVExev2ibIVaypNgCjtZBSZpNEdJQqWnKhD3icROMALTGK7DXsyeSUYEcQsyRdow/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 学习途径  
### B站红队公益课：https://space.bilibili.com/350329294  
### 网安学习资料：点击下方名片回复"学习网安"  
### 往期好文推荐  
### 网络安全必备：GoSearch工具全解析  
### 应急响应的详解，非常详细  
### 超好用实战系列的渗透攻防命令速查，快来瞅瞅，万一有你需要的呢  
  
  
  
  
