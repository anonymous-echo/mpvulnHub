#  逆向专题分析 - Strcpy缓冲区溢出漏洞   
原创 chobits02  C4安全团队   2025-05-14 08:27  
  
    WELCOME      
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/hgqyI1gBHcmiaoS7tnSh83aWZw0YLv4heYSpnkia8BhFlSF23tfZgrbRE5rdcgHc4g7euMqgXW4xZcVu9kibj3ltg/640?&wx_fmt=png&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
网络安全·诚邀合作  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/bGJ4zw731flz5kBrMicZeXsZ3NHiaC4QujdKfatMJlHNc4mkNyc1OjBGaNkbvhYuouE92yicLARwq6g9hz8wBoLHA/640?&wx_fmt=png&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
    我们  
C4安全团队是一支**专业**  
、**高效**  
、  
富有**经验**  
、  
团结的信息安全服务团队，由一群经验丰富、技术精湛的安全专家组成，他们在网络安全领域都有各自发光发亮的地方和大量的实战经验。**在红蓝攻防、日常渗透测试、CTF比赛中也获取很多优异的成绩，帮助客户解决了很多安全问题，得到了客户的认可。欢迎合作咨询！**  
  
****  
![febc6a0067018c67c8984bc9156de031_640_wx_fmt=png&from=appmsg&wxfrom=5&tp=webp&wx_lazy=1.webp](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJT7AzyPll3BkGK2UWYiaa1TPxCY5CRAFe3jHsjbZfelNtvTU0OmOu9XLkibzuicfHh9Bc1g60TORbVYg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**扫描二维码**  
  
**联系合作**  
  
  
  
  
  
## 原文作者：本团队师傅chobits02  
## 原文发表时间：2020年，本文章仅做搬运  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT7AzyPll3BkGK2UWYiaa1TPJhFwaxmDiagSgKxEwdkCCMaYsg7ia5wJGYiclz2gGriaUc9zJDa2zgyVUw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
缓冲区漏洞千千种，这次遇到实验才来讲一讲我想明白的题目  
  
**利用栈溢出漏洞破解口令**  
  
C语言  
源码：  
```
#include<stdio.h>
#include<string.h>
#define PASSWORD "1234567"
int verify_password(char* password)
{
int authenticated=0xEEEEEEEE;
char buffer[8];
printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
authenticated=strcmp(password,PASSWORD);
printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
//printf("flag的值为：%d\n",authenticated);
strcpy(buffer,password);
printf("%s\n",buffer);
printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
//printf("覆盖以后flag的值为：%d\n",authenticated);
return authenticated;
}

int main()
{
int valid_flag=0x0;
char password[8];
printf("please input password:");
scanf("%s",password);
//printf("传的值为：%d\n",verify_password(password));
valid_flag=verify_password(password);
//printf("传完之后flag的值为：%d\n",valid_flag);
if (valid_flag)
    {
        printf("incorrect password!\n\n");
   }
else
    {
        printf("Congratulation! You have passed the verification!\n");
   }
}
```  
  
需要达成的  
目标如下  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l1ZKPMwiaTJBNwP43r3iaFaWibf9icrVzUYWLNd8Cicz4YHDpiatO7OmovROyA/640?wx_fmt=jpeg&from=appmsg "")  
  
01.首先  
  
观察一下程序，能判断造成栈溢出的代码是：  
```
```  
  
把上面C语言代码中执行到调用  
verify_password  
函数的堆栈来画一下，从上往下看  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l1giapFgbP16N3BWThykVO9MP8IibhBBzQDlUFm09e9Kd33mIU0icqnk0pg/640?wx_fmt=jpeg&from=appmsg "")  
  
2.分析  
  
来分析一下代码的作用，我在图中给师傅们标出来了  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l1ib1UdXTfuYCZmNsErluUSAjbSZwJM5SB2Y2xs6PHEGwNhlxIyyMHmzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
（注：strcpy比较的是ASCII值，数字输入时虽然是“数字”，但是它是字符串）  
  
我们能够使用  
strcpy方法  
覆盖并修改  
return给main函数的值  
，让main函数误以为我们输入了正确的密码  
  
看下面代码知判断密码正确的flag值为0，否则为不正确（包括大于0和小于0），因此我们就要return给valid_flag一个0  
  
  
3.运行分析  
  
首先运行C语言代码  
  
运行后根据提示，输入12个2，因为buffer最多存8个字节，会溢出4字节到紧接着的堆栈，字符串结尾还有00（'\0'）也要存储  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l1y2uLesnmbRibj65UiawiaicQrIKaw2MmBrXNexZcniaJpSeONDttu3WARRg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l1kvKHKicpdibmNYKMnk0ZjjwuLEHVqq1fVeM63bXxwTNia4egnKEVWn3fw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l16sNkiaTAREBvxh5ZbYG9atiaicwltPjVvsJxpibwOeBltnMJicU4HsSHxTw/640?wx_fmt=jpeg&from=appmsg "")  
  
此处可见flag值被结束符00覆盖了，因此被误认为输入正确  
  
   
  
4.特殊情况  
  
如果输入12个1为什么会认为输入错误呢？  
  
首先strcpy是  
逐位比较  
，遇到不同位相减返回值的，输入12个1，遇到第二位2时，1-2=-1，因此返回-1（  
16进制存的是补码为FFFFFFFF  
）  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQJ6kckicpHl7iaFpoeRzw9l1ic2hUs87GvMTH0EDicccbwibP4Y5NusqGDicyicx0ACq9MUxKAjETWetCoA/640?wx_fmt=jpeg&from=appmsg "")  
  
因为return的值即flag位的数为负数，存储时补码占4字节，虽然字符串有结束符00，但是还远远不能覆盖，返回的值不为0，因此被判断为输入错误  
  
   
  
实际上只要输入的字符为12位，且第一个不同位的ASCII值比预设密码的那位ASCII值大就能绕过密码的判断了。  
  
  
****  
**专栏介绍**  
  
Freebuf知识大陆内部共享资料截屏详情如下  
  
（每周保持更新，已更新 170+文档，扫码可免费预览）  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkzvdgfFtJotO7T8dD5ATKyyeuQibDwZoltOB3Uy5nRicGDxCEpwrlRYNg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT7AzyPll3BkGK2UWYiaa1TPXPpichRjSPC19Mfy8sblsdtsoUsJhCn4SbVmlGgeibKTkD8Ima1icVic8Q/640?wx_fmt=png&from=appmsg&wxfrom=5&tp=wxpic&wx_lazy=1 "")  
  
  
**知识大陆——安全渗透感知大家族**  
****  
  
圈子券后现价   
￥39.9元  
  
（新人优惠券折扣  
20  
￥，扫码即可领取优惠）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJR7GIiatmMxDnlYcGJjOmibZcd7ribwq1zichkjwIczCqhZ1zpXib3VcJpMWlSLfa6qpXwfVy6hguOXdibA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
内部圈子——  
群  
友反馈，价格优惠，内容优质  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkZXuRl4vOBsaQwJK1AbsPcGMiczaPickCuIzicPiblfFjyjic3aeuzqVLLhg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkpxDWia5shmzQH4UialWGUCsoWYMHVpcEtUxF7RsfJaHKl9gsVWEjqAuw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
团队公开交流群  
  
QQ群和微信群都已建立，方便常用QQ或微信的师傅加入团队公开交流群，交流各类网安、实战方面的问题~  
  
（微信群①群已满200人，需要邀请加开头运营二维码才能加入，②群如下）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJRuhpLqv9vp6hK42MwA2UP9bCsu0cYvbibPjCGWHJVxSTe5WsvSjqzeZnakI8oic6kjtHIggwhEGpyg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
  
