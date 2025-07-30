#  悟空crm漏洞新用   
原创 mazihan  Tide安全团队   2022-09-28 17:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXu3bXekvbOVFvAicpfFJwIOcQOuakZ6jTmyNoeraLFgI4cibKrDRiaPAljUry4dy4e2zK8lUMyKfkGg/640?wx_fmt=png "")  
  
  
  
### 概述  
  
悟空软件长期为企业提供企业管理软件(CRM/HRM/OA/ERP等)的研发、实施、营销、咨询、培训、服务于一体的信息化服务。悟空软件以高科技为起点，以技术为核心、以完善的售后服务为后盾，秉承稳固与发展、求实与创新的精神，已为国内外上千家企业提供服务。  
听说很厉害，搜索了下存在的旧版本漏洞，看看是否还存在这样的漏洞，旧漏洞如下:  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYU0ayYSUDJgzdM8fGicibAxJOEYVITqwtFdAaeTMKjHBdfFLjrm5UQoruQ/640?wx_fmt=png "")  
按照已有的方向先排查一波。### 安装  
下载路径：https://gitee.com/wukongcrm/crm_php下载完包后，解压放到环境的根目录。访问url:  
www.wk.com/index.php/admin/install/index.html  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUs3l2MTGjQ8wVLbem6wArq2cUpyIkXJDlA0b68dp3K6X3duFT9Ka5UQ/640?wx_fmt=png "")  
点击同意，进行下一步安装。  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUcmKEGM7TibIJY9pw26bibiaAyUicT6KGSMl4D3xM7G5S1WhcZlKk8R4RvQ/640?wx_fmt=png "")  
安装完成，使用安装过程功的账号密码，登录到工作台。  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUeRQrkRw6jxNggakk5EsS2JvHYZVwRto0RqlBFCUngnlfVSLVwFhib6g/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUJtqkBsibibFT3RQ0tWM4Dc8VPIFcoZw7dtR6PzDc8MGj3ApEicJYh43tw/640?wx_fmt=png "")  
### sql注入  
进入到管理操作区，找到项目管理，在所有请求中有一个myTask请求，  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUc8U60Of2ultaDw4ck1hbMXrTjkia3JFuicqok1KRKz8aoQSy8F6CgewA/640?wx_fmt=png "")  
使用burpsuite抓取到改请求，发送到重放模块，接着修改构建传递的参数，第一个将url部分mytask修改成dateList,将body部分的{"search":"","sort_field":2,"completed_task":true,"owner_user_id":[],"time_type":"","label_id":[]}修改改成{"start_time":"123","stop_time":"12"}
此时点击一次go，看是否有正确相应。  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUhSgatmNFohQp3mM0guD8BqxGiaW5VpdkibMc25Z2Xt7mVMktxd9HG2lg/640?wx_fmt=png "")  
  
接着，将请求保存到一个文本中，命名为post.txt。接着上sqlmap跑一下这个请求包。  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUd7BfreKzGnq2ibkt9EcVW34dic0DiaIuXNVfMV93K3RsABzkZUWWbNyIg/640?wx_fmt=png "")  
  
代码分析：  
```
    public function dateList()
    {
        $param = $this->param;
        $taskModel = model('Task');
        $userInfo = $this->userInfo;
        $param['user_id'] = $userInfo['id'];
        $data = $taskModel->getDateList($param);
        return resultArray(['data' => $data]);
    }
```  
  
此方法中的getDateList读取数据库，看方法逻辑：  
```
public function getDateList($param)
    {
        $start_time = $param['start_time'];
        $stop_time = $param['stop_time'];
        $user_id = $param['user_id'];
        // $date_list = dateList($start_time, $stop_time, 1);
        $where = [];
        $where['ishidden'] = 0;
        $where['is_archive'] = 0;
        $where['status'] = 1;
        $where['pid'] = 0;
        $str = ',' . $user_id . ',';
        $whereStr = ' ( create_user_id = ' . $user_id . ' or ( owner_user_id like "%' . $str . '%") or ( main_user_id = ' . $user_id . ' ) )';
        $whereDate = '( stop_time > 0 and stop_time between ' . $start_time . ' and ' . $stop_time . ' ) or ( update_time between ' . $start_time . ' and ' . $stop_time . ' )';
        $list = db('task')
            ->where($where)
            ->where($whereStr)
            ->where($whereDate)
            ->field('task_id,name,priority,start_time,stop_time,priority,update_time')
            ->select();
        return $list ?: [];
    }
```  
再此方法中接受的参数有start_time、stop_time、user_id三个参数，其实这三个参数都没有加过滤，直接字符串拼接。所以都存在SQL注入点，只不过sqlmap在start_time的时候，就跑出结果了，后面不验证罢了。需要提醒的是，再最新版本中，这个url需要构造出来，而不是点解控制台中哪个url。项目方把这个功能模块去掉了，但是代码并没有删除。简单验证如下图：  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUW19Hic9WnoB4njZayRsZGURtappsAO51iccczZQ0h9FQeIvc2YAkJMOw/640?wx_fmt=png "")  
所以，前台的vue打包程序中，没有这个路由了。只能通过后期的构建，才能复现出这个漏洞。### 任意文件上传  
在平台所有文件上传点上，选取上传用户图像的功能点。  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUYs4AQO8alpicumGpy3PxAictibBBsB4u2RbMfFDKVllibRM5h5bk2ayfoA/640?wx_fmt=png "")  
使用burpsuite抓包，如下：  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUVP5VyVYyk000TYRrx1RCWplEiaZYyXnBZFBmEjF5nib95FNuhTS2CHeA/640?wx_fmt=png "")  
  
将用户名和图片内容分别替换成php后缀的文件，和PHP代码如：此时返回的数据是错误的，不过没关系，文件已经生成了。如下图所示：  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUdSbYDca0tev2DIvzIH1LHOwuJ6f2LHvvwujXYZ3rJXoFNZYZywrCPg/640?wx_fmt=png "")  
尝试了很多次，生的文件比较多。此时从浏览器上访问任意一个文件路径，效果如下：  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYU60JLovLxiczF5VDlBMIficiaJPxsJNT5Vvt4XvP497s9EXQqx2ZUnwjfA/640?wx_fmt=png "")  
当写入一句话的时候，也是可以用蚁剑连接的。  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUEKDQOUyfNJlzUl0kcDj8yQz1hticak4y2ia2fxYBhCFriaNpjEvWhoCaA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUN51ocRgEeucKe3L1NFoAxYJuxtf3iaicgXTWvo6aUProccQ2kAjicviaPQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUib4ax32J7svEZX76korLIosaDUBryfus89AZvsK7lLPDRUibsePcpdSQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXcx3WXlo2Giboic5icpQVOMYUoYtbY6R9MLzDfLt4mrGIFaPmUIssguZGJBIAXezgW0XT4JyfAyVoyg/640?wx_fmt=png "")  
  
代码分析：通过抓包，访问的url/index.php/admin/users/updateImg  
可以看到该方法如下：```
    public function updateImg()
    {
        $fileModel = model('File');
        $param = $this->param;
        $userInfo = $this->userInfo;
        //处理图片
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: POST');
        header("Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept");
        $param['file'] = request()->file('file');
        
        $resImg = $fileModel->updateByField($param['file'], 'User', $param['id'], 'img', 'thumb_img', 150, 150);
        if (!$resImg) {
            return resultArray(['error' => $fileModel->getError()]);
        }
        return resultArray(['data' => '上传成功']);
    }
```  
  
在方法里，有个updateByField的方法，这个是上传文件的调用，方法体如下：  
```
public function updateByField($file, $module, $module_id, $field, $thumb_field = '', $x = '150', $y = '150')
    {
        if (empty($module) || empty($module_id) || empty($field)) {
            $this->error = '参数错误';
            return false;
        }
        
        $info = $file->move(FILE_PATH . 'public' . DS . 'uploads'); //验证规则
        $fileInfo = $info->getInfo(); //附件数据
```  
  
在这个方法中，有个文件管理类file，其中的move方法做了文件的上传操作，如下：  
```
public function move($path, $savename = true, $replace = true)
    {
        // 文件上传失败，捕获错误代码
        if (!empty($this->info['error'])) {
            $this->error($this->info['error']);
            return false;
        }

        // 检测合法性
        if (!$this->isValid()) {
            $this->error = 'upload illegal files';
            return false;
        }

        // 验证上传
        if (!$this->check()) {
            return false;
        }

        $path = rtrim($path, DS) . DS;
        // 文件保存命名规则
        $saveName = $this->buildSaveName($savename);
        $filename = $path . $saveName;

        // 检测目录
        if (false === $this->checkPath(dirname($filename))) {
            return false;
        }

        // 不覆盖同名文件
        if (!$replace && is_file($filename)) {
            $this->error = ['has the same filename: {:filename}', ['filename' => $filename]];
            return false;
        }

        /* 移动文件 */
        if ($this->isTest) {
            rename($this->filename, $filename);
        } elseif (!move_uploaded_file($this->filename, $filename)) {
            $this->error = 'upload write error';
            return false;
        }

        // 返回 File 对象实例
        $file = new self($filename);
        $file->setSaveName($saveName)->setUploadInfo($this->info);

        return $file;
    }
```  
  
到此，方法体中的move_uploaded_file算是保存完了构建的PHP文件，需要注意的是，这里的命名规则，代码里用了时间的随机数，  
```
   switch ($this->rule) {
                    case 'date':
                        $savename = date('Ymd') . DS . md5(microtime(true));
                        break;
```  
  
也就是说，前端可以猜到具体的文件夹，但是具体的文件名，需要后期做个碰撞的脚本，才可以获取到。因为是白盒审计，这一步就暂时省略掉了。  
### 总结  
  
老版本种存在的问题，最新版本也是存在的，只不过需要后期数据的加工，没有之前版本来的那么容易。所以做程序要用心，做安全更是如此。  
  
  
E  
  
  
  
  
N  
  
  
  
  
D  
  
  
  
  
  
**关**  
  
  
  
  
**于**  
  
  
  
  
**我**  
  
  
  
  
**们**  
  
  
  
  
Tide安全团队正式成立于2019年1月，是新潮信息旗下以互联网攻防技术研究为目标的安全团队，团队致力于分享高质量原创文章、开源安全工具、交流安全技术，研究方向覆盖网络攻防、系统安全、Web安全、移动终端、安全开发、物联网/工控安全/AI安全等多个领域。  
  
团队作为“省级等保关键技术实验室”先后与哈工大、齐鲁银行、聊城大学、交通学院等多个高校名企建立联合技术实验室，近三年来在网络安全技术方面开展研发项目60余项，获得各类自主知识产权30余项，省市级科技项目立项20余项，研究成果应用于产品核心技术研究、国家重点科技项目攻关、专业安全服务等。对安全感兴趣的小伙伴可以加入或关注我们。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUGxmZ0l89buUNbyVALKxic2nM7hnDCkAKIrjKhdcDfVkGq3PxNzgs7m55BBMwmicc0AvFpYcrd6J6Q/640?wx_fmt=jpeg "")  
