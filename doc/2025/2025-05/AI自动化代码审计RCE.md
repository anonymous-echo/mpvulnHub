#  AI自动化代码审计RCE   
bcloud  安全洞察知识图谱   2025-05-12 02:15  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1实战过程  
```
原文链接：https://xz.aliyun.com/news/17327
如侵权请私聊我们删文
```  
# 前言  
  
AI最近的趋势持续偏高，用AI来写代码，挖漏洞甚至于审计代码的文章或者工具都非常多，最近刚好在学习AI安全，并且php相关的代码审计也比较熟练，趁着学习AI的机会结合代码审计进行学习。  
# 智能体创建  
  
代码审计分很多类型，其中有的类型为传入大模型大量文件，让其进行分析，还有的就是传入一串你觉得存在漏洞的代码进行分析。  
  
这里使用互联网上开源且免费的AI聊天机器人创建一个关于代码审计的智能体  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibk1IiabNYq4Y9c1LPcCMqwUuictGs2Nu8Iibxr5tNvyuKhwMqzxzM32ibDicw/640?wx_fmt=jpeg "")  
# RCE  
  
创建成功后，查看如下代码，大家可以发现在system("cp ".$target_path." /xxxxxxxxx/dmconfig".$_POST['url']);  
这行代码中存在存在命令执行且参数可控，但看这一行代码的话相信只要是小白应该都能够构造出payload,但是问题是还有一些前置条件。  
```
<?php

if (   isset($_POST['pwd'])
    && 0 == strcmp($_POST['pwd'], "nv2260")
    && isset($_POST['url']) )
{
if ($_FILES['file']['error'] > 0)
    {
header("Content-Type: text/plain");
echo"error: " . $_FILES['file']['error'] . "\n";
exit(0);
    }
else
    {
if ($_FILES['file']['size'] > 10*1024*1024)
        {
header("Content-Type: text/plain");
echo"error: file size is too large\n";
        }
else
        {
$target_path = "/xxxxxxxxx/odmconfig".$_POST['url'];
//Create in-between folders if not exists
$dir_name = dirname("/xxxxxxxxx/odmconfig".$_POST['url']);
if(!file_exists($dir_name))
            {
mkdir($dir_name, 0644, true);
            }

if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path))
            {
//Create in-between folders if not exists
$dir_name = dirname("/xxxxxxxxx/dmconfig".$_POST['url']);
if(!file_exists($dir_name))
                {
mkdir($dir_name, 0644, true);
                }

system("cp ".$target_path." /xxxxxxxxx/dmconfig".$_POST['url']);
header("Content-Type: text/plain");
echo"upload ok\n";
            }
else
            {
header("Content-Type: text/plain");
echo"error: there was an error uploading the file, please try again!\n";
            }
        }
    }
}
else
{
header("404 Not Found");
exit(0);
}

?>
```  
  
把上述代码丢尽AI智能体中进行分析，可以发现成功给出了漏洞类型，位置以及攻击流程和payload等等。并且我们通过上述代码是可以知道提交的请求包是POST请求且以文件上传的格式进行RCE的，因此对于AI来说这也不是什么问题。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkrRRRq8qCic6hO2VPvGmIR7jp9aJ3yx2qyLbkpy28aJ0p86feHer5GuA/640?wx_fmt=jpeg "")  
  
如果上述给的payload不符合你的要求，你可再次进行询问，比如说想要使用python代码提交请求，或者BURP，yakit来发送恶意请求包都可以，如下图：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkia3hlMr3e7XpCu3V6aUKHSDKUhibZYs9mbvVyMr3BlbMU57O62F6GBCA/640?wx_fmt=jpeg "")  
  
通过AI智能体构造的恶意请求包（只需要稍加更改路径或者格式即可），发送请求即可发现成功执行whoami命令造成RCE  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkrMd2Y4uynTrN2vQTVSe8V9Arfb0uhhcicz3WwpuIq1F5yK6bY5txXyg/640?wx_fmt=jpeg "")  
# RCE  
  
我们在来查看这一段代码，这一段代码稍加复杂一点点的地方在于命令构造方面，且涵盖的变量稍多，如果自己分析的话可能需要一点时间  
```
if (isset($_GET['cmd']) )
    {
if(){...}
elseif( 0 == strcmp($_GET['cmd'],'writeuploaddir') )
        {     
if(constant("NEED_UPLOAD_FROM_DISK"))
            {
if (isset($_GET['uploaddir']))
                {
$uploaddir = $_GET['uploaddir'];
$fp = fopen(UPLOAD_CONF_PATH, 'w');
$strData = "server.upload-dirs=(\"" . $uploaddir . "\")\n";

                    fwrite($fp, $strData);
                    fclose($fp);

$current_dir = system('cat '.PHP_CINF_PATH.'| grep \'upload_tmp_dir\'');
$tmp_upload_dir = 'upload_tmp_dir='.$uploaddir;
$cmd = "sed -i 's/".str_replace('/', '\/', $current_dir)."/".str_replace('/', '\/', $tmp_upload_dir)."/g/g' ".PHP_CINF_PATH;

                    system($cmd);
                    //system("echo \"$uploaddir\" > ".UPGRADE_DIR_PATH);
$file = fopen(UPGRADE_DIR_PATH,"w");
if( $file )
                    {
                        fwrite($file,"[UPLOAD]\n");
                        fwrite($file,"upload_dir=\"". $uploaddir ."\"\n");
                        fclose($file);
                    }
                }
            }

            header("Content-type: application/xml\r\n\r\n");
echo"Modify upload directory ok";
        }

```  
  
直接把代码丢给智能体压力一下AI，可以发现给出了两个漏洞位置，其中漏洞位置1给出了payload示例。  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkicT2ftpw2s2jibqU85BCrsUbJhMXwJJYcfmBLASxFFbwddxLRdibpfTYg/640?wx_fmt=jpeg "")  
  
但是通过上图发现给出的payload示例不够完整，不能直接如第一个RCE一样直接用即可，因此我们可以询问AI详细的构造方法应该是怎样的，怎么样才能在这条命令里面加入whoami命令并成功执行等等传递给AI，如下图，通过询问构造方法相关问题，直接输出构造恶意whoami命令的payload  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkXGrlXfbabTIfANkTlkiaH9Y0QIKoz6bXEv1WHFuiaj5QNU5HRgHMGorw/640?wx_fmt=jpeg "")  
  
直接结合上下文所有的payload发包，成功RCE  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkibElrgC25EZYU00SPruJ9r4qiccevKFwKBiaWWuHTA5VyzsicD4YLYocpg/640?wx_fmt=jpeg "")  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rhic2eSUB7oxwhHPcGA4rxBibkzK2yZDWbEbIFUicsiaIvKBicJpoAGWD0TsCuglicbPcQsyKrmIibvHiaGWDA/640?wx_fmt=jpeg&from=appmsg "")  
  
