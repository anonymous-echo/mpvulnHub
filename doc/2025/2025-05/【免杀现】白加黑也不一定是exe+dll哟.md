#  【免杀现】白加黑也不一定是exe+dll哟   
原创 xiaocaiji  网安鲲为帝   2025-05-16 14:11  
  
**0x00****免责声明**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
本  
文  
仅  
用  
于  
技  
术  
讨  
论  
与  
学  
习  
，  
利  
用  
此  
文  
所  
提  
供  
的  
信  
息  
而  
造  
成  
的  
任  
何  
直  
接  
或  
者  
间  
接  
的  
后  
果  
及  
损  
失  
，  
均  
由  
使  
用  
者  
本  
人  
负  
责  
，  
文  
章  
作  
者  
及  
本  
公  
众  
号  
团  
队  
不  
为  
此  
承  
担  
任  
何  
责  
任  
。  
  
  
**0x01 利用过程**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
1.无意中在每个软件安装目录发现了一个加白的info.exe文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEKRoILfxVNXALiawcHMVeeF1RQg53zUC08ufpnVorDmVpFKbDzjaf50cOHWSZeiaXe9Itk3RPrPvHzg/640?wx_fmt=png&from=appmsg "")  
  
2. 通过ida分析加白的程序，发现加白的程序它能够调用对应的exe文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEKRoILfxVNXALiawcHMVeeF1xpgwO7iazgDnELouSugRBt7aOyiaQATMBhLjS7O6s0hfeOAgepQW6lHg/640?wx_fmt=png&from=appmsg "")  
  
2.编写测试文件  
```
#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

int main(int argc,char *argv[])
{
	::MessageBoxA(0, "hello", "test", 0);
return 0;
}
```  
  
测试文件正常运行效果（会有正常的黑框也是360注意的地方）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEKRoILfxVNXALiawcHMVeeF1FwoAwftec1z3KZfsYI2qvVmvqNPk2Xy1l13Col53nqBKss8tozPEew/640?wx_fmt=png&from=appmsg "")  
  
  
3.将我们的加白文件命名为我们分析的文件名称与info.exe放在同一个目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEKRoILfxVNXALiawcHMVeeF1v3hEPzHpn8wlibj8Q5no7EYEtOGnmrXb01SqymKCHsQNibxSlmYVevLw/640?wx_fmt=png&from=appmsg "")  
  
  
4.然后将加白的文件与我们的exe放在杀软环境下能够成功运行，而且也能成功的给我们处理调黑框，再会因为隐藏黑框被杀而焦虑了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEKRoILfxVNXALiawcHMVeeF1N7zIkstWcGnvffTv8CHFygPYR4ZOzfEtH8axTjA4axX2H18uU3gRgQ/640?wx_fmt=png&from=appmsg "")  
  
  
5.加载后我们的进程截图（  
建议用于钓鱼最好不过了）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEKRoILfxVNXALiawcHMVeeF1gc6C4Q2lNwWicprl9HHL49HdWEyhdHty7ibUibUfpZbY8rk9MAfpibP3LA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 深入交流群**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
文件已发布到纷传圈子，师傅们要进的抓紧哦！后续价格只增不减，错过机会难再遇哦！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VELiclpicHoicoYfvibSxRClmxsZuCkLVI6mxpttTQj03nf0QAapfvd228MSTuPoqHVz2eKSwxM5ib18CAw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**0x06 欢迎进群交流**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
添加微信进群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJdfiaGbzW6sp0kFvhYC7ejuJuS6lWyHyUGg40F2QVic6goic34EbYceQ2WE4eyMZ8oxbswQkhzJLhNQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
      
  
  
  
