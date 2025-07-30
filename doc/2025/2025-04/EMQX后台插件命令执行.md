#  EMQX后台插件命令执行   
原创 yudays  yudays实验室   2025-04-09 22:56  
  
欢迎转发，请勿抄袭  
        EMQX（简称 EMQ）是一款完全开源、高度可伸缩且高可用的分布式 MQTT 消息服务器。它不仅支持 MQTT 协议，还支持其他 IoT 协议如 CoAP/LwM2M 等，适用于物联网（IoT）、机器对机器（M2M）通信以及移动应用程序。常用于物联网设备与web控制的系统。  
  
一  
  
**前置条件**  
  
1、有账号密码  
  
2、版本<5.8.6 版本  
  
二  
  
靶场制作  
  
准备一个EMQX环境，本次测试环境使用docker部署。  
```
docker pull emqx/emqx-enterprise:5.5.1
docker run -d --name emqx-enterprise -p 1883:1883 -p 8083:8083 -p 8084:8084 -p 8883:8883 -p 18083:18083 emqx/emqx-enterprise:5.5.1
```  
  
运行容器后访问  
http://ip:18083  
登录页面如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2iaK9PIZ1lA957zjVKK85gqskCRNMyiac7IOc1vicCoYzfD58iasuRTniaiaA/640?wx_fmt=png&from=appmsg "")  
  
使用默认口令admin/public(提示密码需要修改，点击跳过即可)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2KZrv8WE9keYWaqbhUuWBtKUSxBEhWrAoY5060PcNyVzEhGict748exQ/640?wx_fmt=png&from=appmsg "")  
  
可根据左下方确认版本。  
  
三  
  
**制作恶意插件**  
  
以kali系统镜像制作编译插件环境  
  
1、配置网络代理，需要下载依赖  
```
export http_proxy=http://192.168.160.1:10809
export https_proxy=http://192.168.160.1:10809
```  
  
  
2、安装相关软件以及依赖  
  
```
sudo apt update
sudo apt install -y build-essential autoconf libncurses5-dev libssl-dev libwxgtk3.2-dev libgl1-mesa-dev libglu1-mesa-dev libpng-dev libssh-dev unixodbc-dev cmake
git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v0.13.1
echo '. "$HOME/.asdf/asdf.sh"' >> ~/.bashrc
echo '. "$HOME/.asdf/completions/asdf.bash"' >> ~/.bashrc
source ~/.bashrc
asdf --version
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2huTandlMyX6GIMWN74vk7044IetXX9Ix2c4oyP3gTgFlEnSJD03Upg/640?wx_fmt=png&from=appmsg "")  
  
3、安装erlang、rebar3  
```
asdf plugin-add erlang https://github.com/asdf-vm/asdf-erlang.git
asdf install erlang 25.3
asdf global erlang 25.3
wget https://s3.amazonaws.com/rebar3/rebar3
chmod +x rebar3
sudo mv rebar3 /usr/local/bin/
```  
  
  
4、创建插件  
```
rebar3 new emqx-plugin my_emqx_plugin
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2CEMFF1LK50UCLzlQNF3vgOiaCLdqZbHeYt3va3cUObg9JH4oeHmicibdA/640?wx_fmt=png&from=appmsg "")  
  
5、修改恶意执行脚本  
```
vim my_emqx_plugin/src/my_emqx_plugin.erl
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2yDdiaMuIZ0Apvqj2zbJVsXlCGmp6xeQzzmkt7Xeenog5qoQRubxMMnQ/640?wx_fmt=png&from=appmsg "")  
  
6、编译插件并复制出来  
```
make -C my_emqx_plugin rel
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2yWNwx5rPGtlMJiccsbqFhjY4fDIibI60xfk0SDGwFaw4hWAic85unDKXg/640?wx_fmt=png&from=appmsg "")  
```
cp my_emqx_plugin/_build/default/emqx_plugrel/my_emqx_plugin-1.0.0.tar.gz .
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2h0pqHQI3biaWdia6a2bOSJLsbpRUjRYhLVt1n2n4wyK03ibQ3V0kxb3Lg/640?wx_fmt=png&from=appmsg "")  
  
四  
  
**7、执行恶意插件**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2w4LWvwGZqxveI9VfFwbu91H7wjianqKicdZw2I7fRvj646rfWXFsdfibw/640?wx_fmt=png&from=appmsg "")  
  
将刚才生成的恶意插件上传到后台，并启动插件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2heMARbWvUUXtOSuj41ibuJGrca8HaAHSb573pnziaH4cuAI9qyUQNbtQ/640?wx_fmt=png&from=appmsg "")  
  
执行完后到服务器查看tmp目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2V7OFhDm8UW7EkiaYAXicJaWsTegHXRYWQDKMicFRf5poYBQ58FjZq0Z1A/640?wx_fmt=png&from=appmsg "")  
  
tis：高版本默认不开启插件安装功能。安装什么插件就得执行允许安装什么插件的命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXmt8N6jjEeuRAkuqabewUy2kP7fiaLaEqN3S92KBiar5WcVyj083N1utibbkOfiaVDNZ0RCOvYndHh8KQ/640?wx_fmt=png&from=appmsg "")  
  
参考：  
  
https://github.com/ricardojoserf/emqx-RCE  
  
  
文章声明：该工具、教程仅供学习参考，请勿非法使用。否则与作者无关！  
  
  
    
  
