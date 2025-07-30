#  Linux提权系列18: [训练营]利用linux能力漏洞1   
原创 debugeeker  奶牛安全   2023-04-12 08:05  
  
正如在上一篇文章中讨论的能力，有 40 种  
能  
力，但从信息安全的角度来看，将讨论其中的大约 20 种。  
## CAP_SETUID  
  
要获取至少具有一种  
能  
力的文件，可以使用 getcap -r <directory> 2> /dev/null 进行 getcap 递归搜索。将标准错误重定向到 /dev/null 非常方便，就好像文件没有任何能力或不允许读取能力一样，它会抛出错误  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSXPsU4oKN5ziacmsMsLibYho23Ga0L0jPhguA9aMUmg8JbIZ8K9djxjicQ/640?wx_fmt=png "")  
  
由于 python 解释器在有效集中允许使用 cap_setuid，这意味着它可以任意设置用户 ID。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSEkWwq0iaiad2nynOuDc1H8jgUdoeWicVqoqOAiawFemvRzxaRgTPHbXtRg/640?wx_fmt=png "")  
  
现在可以导入 os 模块并调用 setuid 函数，该函数将在内部调用 setuid 系统调用并将权限提升为 root 用户，组 ID 与当前用户student相同  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSia9LSUuk40BgeB9romAZfxibibicDa0LxtQTUQu1DJiaID1WdPkiaqzWXITg/640?wx_fmt=png "")  
## CAP_SETUID 2  
  
在根目录中递归查找  
能  
力时，发现 python2 解释器再次设置了 cap_setuid  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucS3QD3QiaQu4bjqicYvQiaBntJCtH8k4wodeUiby0Nm5ufuPq7ThHXWghxHA/640?wx_fmt=png "")  
  
如果仔细观察，这次它在允许集中。因此，如果尝试将 UID 设置为 0，它将失败的地方将是“不允许操作”错误。这实际上是有道理的，因为内核将在有效集中而不是允许集中寻找  
能  
力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSlHS7UmOGxNCGgYSCjPVHAML6Bd4qslcPS75o1lJYzEfsRny2vVXHnA/640?wx_fmt=png "")  
  
但是，可以通过导入 prctl 然后将  
能  
力从允许集转换为有效集来解决此问题。这个执行成功后，调用os.setuid(0)，这次就执行成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucStg5FSfGxUUf4ica5K6zaD8I4WjVnDkT6d0RdWK6vh6xiauWckCwicCmQQ/640?wx_fmt=png "")  
  
如果  
能  
力在允许集中且未安装 prctl，则可以导入 ctypes 模块，加载 libc 并从中调用 prtcl 函数  
```
$ readelf -s /usr/lib/libc.so.6  | grep prctl
   883: 00000000000fedd0   136 FUNC    WEAK   DEFAULT   16 prctl@@GLIBC_2.2.5
  2126: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS prctl.c
  3738: 00000000000fedd0   136 FUNC    LOCAL  DEFAULT   16 __GI___prctl
  3871: 00000000000ff100    37 FUNC    LOCAL  DEFAULT   16 __GI_arch_prctl
  4467: 00000000000ff100    37 FUNC    LOCAL  DEFAULT   16 __GI___arch_prctl
  4586: 00000000000fedd0   136 FUNC    LOCAL  DEFAULT   16 __prctl
  7594: 00000000000fedd0   136 FUNC    WEAK   DEFAULT   16 prctl
  8096: 00000000000ff100    37 FUNC    WEAK   DEFAULT   16 arch_prctl
  8266: 00000000000ff100    37 FUNC    GLOBAL DEFAULT   16 __arch_prctl

```  
## CAP_SETGID  
  
在根目录中递归获取  
能  
力时，发现这次 python 解释器将 cap_setgid   
能  
力设置为有效集和允许集。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucScIfXyqm1FAOtync3W3y93ibsopcBhFfU5CLapjJBL2ELZN1SuzHA3ibg/640?wx_fmt=png "")  
  
当一个程序在有效集合中设置了cap_setgid能力时，可以在程序执行时任意改变组id。这将不允许更改用户 ID。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSAXSN3y9ovg4ny2o1nC71nwFahVScicM97dLLERGreSPq1GfA0S2BmjQ/640?wx_fmt=png "")  
  
这个不能直接生成特权 shell，而是在调用 os.setgid() 函数后，对与当前运行进程具有相同组 ID 的文件执行特定于组的操作。os.setgid()会调用 setgid() 系统调用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSuV6YBAszx2cahuTWk82GE3ql7gz9ds5dqLzmCZjVYaj6mmxFMctzww/640?wx_fmt=png "")  
  
这个实验的描述是，flag是root用户的hash。由于这些文件中的组没有写入权限，因此无法获得特权 shell，但可以读取/etc/shadow文件的内容。由于 setgid 函数需要组 ID，可以在 /etc/group 文件中找到此信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSicwT68R3PpXfJAkMSv7asicp5Rh4cW0SGFksEPLf3NiclAc160icIJmTTA/640?wx_fmt=png "")  
  
现在已经准备就绪，是时候将组 ID 更改为 42 并从 /etc/shadow 文件中读取第一行了。  
  
当使用 open 内置函数在 python 中打开文件时，它会给一个迭代器，读取第一行只需键入执行next(file)函数, file是文件句柄  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSwWicQEsxkPicfMFicCNz6xg3BGUZsycMTdmPhfsCDh2kibMeXdeibwSXqpA/640?wx_fmt=png "")  
  
所以在这种情况下，哈希 Yg .... 1. 记住，$1$ 是哈希类型，$flag$ 是盐，而不是哈希值  
## CAP_SETGID 2  
  
在根目录中递归检查  
能  
力时，发现 python 解释器再次被允许更改组 ID.  
  
这次的flag位于 root 用户的主目录（即 /root）中，但无法以任何方式在 /root 目录中执行任何操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSFIkpQ4nxwXz8vg5YGWBSOicmVZic63dRKgag6gXdTUHEPTRAEgYRqBQQ/640?wx_fmt=png "")  
  
发现当前系统正在运行 docker 服务，因为 docker socket 存在于 /var/run 目录中，并且还安装了 docker CLI。这意味着只要可以运行 docker 容器，就可以接管系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSnE43icdia1pcZnCVcrGo3PWduloWn44M4uahwLGibDBekibGzoDAGcMiaVA/640?wx_fmt=png "")  
  
发现 docker 组可以在 docker 套接字上执行读写操作，从而向 docker 服务发送命令。这不是配置错误，但可以看到运行一个无意的应用程序并使用另一个二进制文件来更改 gid 可能是一个攻击向量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSvAyD0cdH9ibnpTltTzBkFoiblGvKvnvXFC4o58QoRHTXIrc07YkibkRxA/640?wx_fmt=png "")  
  
通过列出 docker 镜像来测试这些。如果没有镜像，那么将再次无法升级到 root 用户。  
  
使用 /etc/group 文件查找 docker 的组 ID，并通过将 gid 设置为 docker 组来从 python 生成一个 shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSmDA0O0uIiaibc8xpQmCiaGV1CLiaibFTTf0Cuia1LYRXFuJbPgoVxEibXfXpQ/640?wx_fmt=png "")  
  
由于 docker 有一个 ubuntu 镜像，很明显它将提供一个 shell 来执行命令。使用 docker 将根目录挂载到容器的 /host 目录中并生成一个 shell。稍后可以使用 chroot 实用程序进入主机的根文件系统并通过 root 用户执行操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbx4m3EpjtHwBLVS3CkMPucSmFnI621z7scphArGwZ4q07ShSNfO7mRtpbyQT8XyAWGSYhOTGyC5aA/640?wx_fmt=png "")  
# 请点一下右下角的“在看”，谢谢！！  
  
  
**暗号：709188**  
  
  
