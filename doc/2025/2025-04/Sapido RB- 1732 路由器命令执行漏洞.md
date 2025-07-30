#  Sapido RB- 1732 路由器命令执行漏洞   
 有限的思考   2025-04-18 05:23  
  
## 漏洞介绍：  
  
Sapido是一款家用路由器，其RB-1732系列v2.0.43之前的固件版本存在一处命令执行漏洞。该漏洞产生的原因是，服务器的syscmd.asp页面没有对传递过来的参数进行过滤，这使得用户的输入没有任何过滤，可以直接将系统命令发送给服务器并在服务器上执行。  
## Fofa特征  
  
app="Sapido-路由器"  
## 固件提取  
  
固件下载：  
  
https://pan.baidu.com/s/1Gj9RDlAQdCDiaLdLzQ2Aag?pwd=8381  
  
使用  
binwalk Me参数提取固件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaYezBDMRzAwzDmrk68tb8O4r4r7dbiaACEqvF2gOwAYePmt9KQu4HUYw/640?wx_fmt=png&from=appmsg "")  
  
解压出来后可以看到文件系统为  
squashfs  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaXE2YWFUUtoB4CkON1vu4jyXsyYwOKSBiaBop5jPg9CIjXZtDORYvoicQ/640?wx_fmt=png&from=appmsg "")  
  
我们已经知道漏洞点在  
syscmd.asp中，我们直接用find命令找到syscmd.asp的位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaxJnD7k4AZBl7hHyCho1JcEtjknIv2V1Ho7qrgMNL9f2UDCGP5RLs8w/640?wx_fmt=png&from=appmsg "")  
  
syscmd.asp位于当前目录也就是解压出来的squashfs-root的web目录下，我们直接打开syscmd.asp文件查看它的源代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiabWtukaeibibAqJtWje53fYKHOSDmrRCtpwAca899icgiblEqFMQXbuycGA/640?wx_fmt=png&from=appmsg "")  
  
看到  
form表单指向了/goform/formSysCmd，接下来我们继续去找formSysCmd文件，find搜索无果后用grep搜索formSysCmd字符串，可以发现大部分都是引用在asp文件中，只有一个结果显示字符串包含在webs二进制文件中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiasU9SKbNnHGnS4Z7k7peJjWeg3sOszcWBsbtjvsBISwwQArljpVbxDg/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
接下来我们用  
ida pro打开这个webs这个二进制文件进行分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEialscc6iaCJiaNEzBpcqb2w3R5Kr6P9vRtOIMYb3rZUItBUiaoEa5JSBQgg/640?wx_fmt=png&from=appmsg "")  
  
在  
ida pro加载webs后按ctrl+f进行搜索，我们的目标是formSysCmd，所以这里搜索“formSysCmd”，找到与之相关的函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiazF25VaHKSsZClaYUnwXr7o2qJneoubqs0ArTuPdLotCLBNvw8ibMrWg/640?wx_fmt=png&from=appmsg "")  
  
这里分别找到地址为  
004044DB和00471A44两处地址，我们先双击004044DB进入到反汇编窗口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiavZsFwDJiaDEPWooqianZ4mQ94E4iaA2RJS0ia1uHm8RJd5YyWXFhZomia0w/640?wx_fmt=png&from=appmsg "")  
  
这里  
ELF32_Sym是ELF的一个结构体，formSysCmd对应的就是formSysCmd函数的实际地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiapzIgIzwCHlicLPYVoibn9HZOmsNm3zqF6G1ymkRhQE2JcrsWXia4X4qHQ/640?wx_fmt=png&from=appmsg "")  
  
用同样的方法再去查看  
00471A44地址处的formSysCmd函数，可以看到这里formSysCmd被解析为ascii字符，在右边注释处可以看到函数偏移量为AA4，单击AA4右边的箭头可以跳转到该函数位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaQ4trRovuEjlW4ND1RiaEJW8XPYKWMQKWE4WazntULIDamujfEnkxf2Q/640?wx_fmt=png&from=appmsg "")  
  
接着双击  
formSysCmd字符串跳转到formSysCmd函数所在的位置，查看其反汇编代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiargiaS7iawAYjMiaBsjOlD0ZjMPCNEMJJ4gA5NBnict5hKiaGavAFIoRVqcg/640?wx_fmt=png&from=appmsg "")  
  
为了方便阅读代码，我们可以按  
f5切换到伪代码窗口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaGRDeGMzf9tkgam3IqdxlKKVaqIrhNObhGsdTlvzbypMd4wvib64YiaCQ/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到  
system函数执行处没有任何过滤，v20的值则是snprintf函数拼接v3的值来复制，而v3是通过websGetVar函数获取sysCmd传递过来的，因此，如果传递给v20参数的值内容是系统命令，则将导致命令执行漏洞。  
## 漏洞复现  
  
漏洞复现需要将固件模拟出真实环境，这里使用  
firmware-analysis-plus进行模拟  
  
github地址：  
  
https://github.com/liyansong2018/firmware-analysis-plus  
  
运行如下命令可直接一键模拟：  
```
python3 ./fap.py -q ./qemu-builds/2.5.0/ ./RB-1732_TC_v2.0.43.bin
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaoGyHEb26AnwD32iaDRpHVJWDumYXlZ6KqOiaGoYyJCmA4U3fOgseAGzg/640?wx_fmt=png&from=appmsg "")  
  
fap在模拟成功后会给出访问地址：192.168.1.1，在浏览器访问http://192.168.1.1，看到如下界面则表示固件模拟成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiaIWvYCBnUPkPI5eG72aJhxia72hotlaFLtdV7wZh7lmeCIjDbjiaO6Pgg/640?wx_fmt=png&from=appmsg "")  
  
输入默认账号密码：  
admin/admin登入后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEia9PU9LgiabcChUO0ZUXKNOTP6J7TOIAeQU021hKybib6QFW3roATQgv2g/640?wx_fmt=png&from=appmsg "")  
  
直接访问  
http://192.168.1.1/syscmd.asp，可以看到一个命令执行的窗口，我们直接输入ls命令，成功执行命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kQXvhdjYREn6So6BKYicJrhiaGibvZtIWEiap8RZkA4VQxZDz2uibU1gQW5A5xnnZcNyxQMcCmibhSCPfwbSHwB7gX3g/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
