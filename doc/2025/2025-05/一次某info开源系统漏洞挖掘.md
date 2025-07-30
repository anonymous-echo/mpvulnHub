#  一次某info开源系统漏洞挖掘   
 进击安全   2025-05-07 13:35  
  
**审计过程：******  
在入口文件admin/index.php中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPutSgklU15rN2MIib8bq2nWQnnib1dPjicN8scaQhpEFBULkMsqwWHI5EDQ/640?wx_fmt=png&from=appmsg "")  
  
用户可以通过m,c,a等参数控制加载的文件和方法，在app/system/entrance.php中存在重点代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuzqzztQ7jWIS4Lgox27icj8olOAphK9Ntbgt2vpyxl1ia8iaicsEWg99kbQ/640?wx_fmt=png&from=appmsg "")  
  
当  
M_TYPE == 'system'  
并且  
M_MODULE == 'include'  
时  
，  
会设置常量  
PATH_OWN_FILE  
为  
PATH_APP.M_TYPE.'/'.M_MODULE.'/module/'  
  
  
也就是路径  
：  
/app/system/include/module   
这个文件夹  
，  
这个点非常重要  
。  
  
  
M_MODULE的值在入口文件中，通过参数传递，导致我们可以控制：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPu2JMlygdT2ez9OiadOV58LPnXF8H0ScbcogYQ2XibeeaTjv96tjoVpXMg/640?wx_fmt=png&from=appmsg "")  
  
M_TYPE的值如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPu0EC0HZs8Zn9Nic0eWAwtVJ04ZAUagibiad9AAvBibGricG2hKiaxeNZnHokg/640?wx_fmt=png&from=appmsg "")  
  
这里M_NAME的值是由我们输入的，只要不赋值即可让M_TYPE的值为system。  
  
  
所以通过对参数m的控制可以设置常量PATH_OWN_FILE为/app/system/include/module 这个点非常重要，后续会用到。  
  
  
继续往后会执行load::module()方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuiamxu8TfQ7aJfPp1BPofTplCEeyGovHLJYx0W2ABKzyNaW1QXDEibzLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuOug2M3O43XK2LqyymZMEuicvtA3QXhSsfEpaXWoq0mN6w6XnfCiaWHrA/640?wx_fmt=png&from=appmsg "")  
  
当module方法不传递任何参数时，会使用默认的参数值，也就是$path = ''，所以这里也就会将$path 的值设置为PATH_OWN_FILE，也就是路径：/app/system/include/module  
  
  
后续的$modulename，$action变量的值也就是我们开头的通过参数a，c控制的值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuFfYPicB8noM8vuFnVGHMXHI6OyumbY93e0qiczT8vQpEqvGNJEBD94yg/640?wx_fmt=png&from=appmsg "")  
  
后续进行self::_load_class($path, $modulename, $action);参数的实现如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuT6OMxTOgBriapIXL2icehWjFf894a9akSjFtDQVJ2MU8xYwA18ia4LS3w/640?wx_fmt=png&from=appmsg "")  
  
该方法就是将文件进行加载进来，并且new出该类的对象后，通过call_user_func进行方法的调用。  
  
  
我们可以在/app/system/include/module目录下寻找到符合xxx.class.php的文件，如：/app/system/include/module/loadtemp.class.php 在给文件中存在doviewHtml方法是我们可以通过web进行调用的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPurXovUkibV9QuU6gWkZAHCp4E8J0W8NtJQKQwxnibUgO0cOc75OvNv4Pw/640?wx_fmt=png&from=appmsg "")  
  
该自研框架通过  
$_M['form']['path'];  
等方式获取到用户的输入  
，  
等同于  
$_POST[  
'path'  
]  
  
  
最后一路执行会来到$view->dofetch的地方：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuHal8rZIuVxcYXrB5qmk6E3AhpNicB5EFwEKYojqU5fShenVQQEtGInA/640?wx_fmt=png&from=appmsg "")  
  
这里我们完全可控$file参数：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuu2xbfqV6mTAY3vxNlZbhmMS9zpH2sTbdIZNWwrtJTHrs6GIIzibx2rg/640?wx_fmt=png&from=appmsg "")  
  
继续跟进fetch方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuvnW3yLqtPBMBSBh1oqSuP4EEeJIkO7D9VhFS74Uj3HhxYHRNuvhBBw/640?wx_fmt=png&from=appmsg "")  
  
跟进display方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuEA6qjXIMU6B4F2POAc09TVU5oWrRMOQlbW1LsEc4lT66kscw1STdfw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPu87L0qglkjzUZTMoYX5YicgFfJvouvDFFN5NUXWXBe4m72wCcYSovPGQ/640?wx_fmt=png&from=appmsg "")  
  
重点关注$this->compile();//执行编译：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuxXF10tAtMFvibjSQK5KxtDuZSeM2C91W5otYPnHPzxfUJhvsPxlWZ3Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuHsYKibvT77yKg4Jd3O1Y1HZTxlLibk2PiapDic1gSHTxNNFgfs1DSQM61Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuEtMYl1Q7ib8O23lice7bNFn2KGQgSufNiaGiag66MpMfQfHmf0jic7icyJtA/640?wx_fmt=png&from=appmsg "")  
  
在执行编译中，将我们输入的文件路径进行了内容读取，将读取后的内容写入到了$this->view->compileFile文件中，返回到开始的display方法中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPu7GiaQoqT8zquQL3LB0HyNBhgibbhYp0FY1icCVYKPsgKvpEWiaGrLicMN0Q/640?wx_fmt=png&from=appmsg "")  
  
通过include编译文件造成了任意代码执行漏洞。  
  
### 文件上传处：  
  
  
/app/system/include/module/uploadify.class.php 文件中的doupfile方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuRAoVKrib4Z4jQm5lobvaDkdu4oDZLYEX3rmtE6jwlwQAHjQXf6RRcLg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuXPugUiaVSKNJbDfXZFp7z49v775JRIMQrDltazgLBPDB6BjKiaTibx3yA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuUdIQGLJxx0eDicLkYibF3DT5FoPPKqFd2vod57RepwCCtIlGbYzY125A/640?wx_fmt=png&from=appmsg "")  
  
可以直接上传白名单内的文件，配合上面的文件包含，造成任意代码执行漏洞。  
  
  
漏洞复现：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RzCEZQRRgcd0cb48uEHiaov27k3418pPuicfIdagw74Cg8lU0a8zc2pXymiaekibFjmviaFa6GjNkspcTQia8W8w51Jg/640?wx_fmt=png&from=appmsg "")  
  
**修复建议：官网已经发布补丁，请及时更新补丁升级版本。**  
  
****  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
  
  
  
  
  
  
****#   
  
  
  
  
  
  
