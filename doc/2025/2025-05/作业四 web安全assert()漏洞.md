#  作业四 web安全assert()漏洞   
原创 豆豆  豆豆咨询   2025-05-31 09:50  
  
一、分析如下代码功能及漏洞，并书写payload  
  
<?php  
  
if (isset($_GET['page'])) {  //判断参数page是否为空  
  
	$page = $_GET['page'];  
  
} else {    //为空输出page=home  
  
	$page = "home";  
  
}  
  
$file = "templates/" . $page . ".php";  
  
// I heard '..' is dangerous!  
  
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");  //查找$file  
  
中..第一次出现的位置，查找成功则返回true，失败则返回flase，  
  
// TODO: Make this look nice  
  
assert("file_exists('$file')") or die("That file doesn't exist!");  
  
?>  
  
<!DOCTYPE html>  
  
<html>  
  
	<head>  
  
		<meta charset="utf-8">  
  
		<meta http-equiv="X-UA-Compatible" content="IE=edge">  
  
		<meta name="viewport" content="width=device-width, initial-scale=1">  
  
		<title>My PHP Website</title>  
  
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css" />  
  
	</head>  
  
	<body>  
  
		<nav class="navbar navbar-inverse navbar-fixed-top">  
  
			<div class="container">  
  
		    	<div class="navbar-header">  
  
		    		<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">  
  
		            	<span class="sr-only">Toggle navigation</span>  
  
		            	<span class="icon-bar"></span>  
  
		            	<span class="icon-bar"></span>  
  
		            	<span class="icon-bar"></span>  
  
		          	</button>  
  
		          	<a class="navbar-brand" href="#">Project name</a>  
  
		        </div>  
  
		        <div id="navbar" class="collapse navbar-collapse">  
  
		          	<ul class="nav navbar-nav">  
  
		            	<li <?php if ($page == "home") { ?>class="active"<?php } ?>><a href="?page=home">Home</a></li>  
  
		            	<li <?php if ($page == "about") { ?>class="active"<?php } ?>><a href="?page=about">About</a></li>  
  
		            	<li <?php if ($page == "contact") { ?>class="active"<?php } ?>><a href="?page=contact">Contact</a></li>  
  
						<!--<li <?php if ($page == "flag") { ?>class="active"<?php } ?>><a href="?page=flag">My secrets</a></li> -->  
  
		          	</ul>  
  
		        </div>  
  
		    </div>  
  
		</nav>  
  
		<div class="container" style="margin-top: 50px">  
  
			<?php  
  
				require_once $file;  
  
			?>  
  
		</div>  
  
		<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js" />  
  
		<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js" />  
  
	</body>  
  
</html>  
  
回答：  
  
代码分析：  
  
a. assert()函数其实是一个断言函数。  
  
assert：这个函数在php语言中是用来判断一个表达式是否成立。返回true or false;assert ( mixed $assertion [, string $description ] ) : bool  
  
　　如果 assertion 是字符串，它将会被 assert() 当做 PHP 代码来执行。  
  
b. strpos() 函数查找字符串在另一字符串中第一次出现的位置，如果没有找到则返回flase，  
  
c. 关键漏洞分析：  
  
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");  
  
由于文件并没有对输入的字符进行过滤，可以进行语句闭合修改语句原本的意思，构建的  
payload:    
 /?page=');//                                            [#双斜杠]()  
 " // " 再php中表示注释  
  
d. payload  
  
假设我们已经知道flag位于/templates/flag.php路径下，payload的构建可以直接一步到位，不用再用system('ls+xxx')回显路径，最后的  
payload：    /?page=').system('cat+./templates/flag.php');//      
  
  
