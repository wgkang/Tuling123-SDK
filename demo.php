<?php

include_once("SDK.php");

$apiKey = 'key';  //你的key    
$secret = '123';  //你的secret

$timestamp = time();
$url = 'http://openapi.tuling123.com/openapi/api/v2';
$aesKey = md5($secret.$timestamp.$apiKey);
$mc = new Tuling123Callback($aesKey, 128);

//参数格式
$encrypt = "{'perception':{'inputText':{'text':'你好'}},'userInfo':{'apiKey':'$apiKey','userId':1}}";

$param = $mc->encrypt($encrypt); 

//请求格式
$json = '{  
    "key":"'.$apiKey.'",
    "timestamp":"'.$timestamp.'",
    "data":"'.$param.'"
}';

//只支持post请求
$resutl = $mc->httpPost($url,$json);

//输出结果  
var_dump($resutl);
    
?>    