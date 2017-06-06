<?php
/*
 *    适用于tuling123 API V1.0和V2.0
 *
 *    https://github.com/gdali/
 *
 *    2007-06-06 
 */
    
class Tuling123Callback {
    private $iv;
    private $key;
    private $bit; //Only can use 64, 128, 192, 256
    
    public function __construct($key = '', $bit = 128, $iv = '') {
        switch($bit){
            case 64: {
                $this->key = Tuling123Callback::crc64($key);
                if($iv != ''){
                    $this->iv = Tuling123Callback::crc64($iv);
                }else{
                    $this->iv = chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0); //IV is not set. It doesn't recommend.
                }
            }
            break;
            case 128:
            case 192:
            case 256: {
                switch ($bit) {
                    case 128:
                        $this->key = hash('MD5', $key, true);
                        break;
                    case 192: 
                        $this->key = hash('tiger192,3', $key, true);
                        break;
                    case 256:
                        $this->key = hash('SHA256', $key, true);
                        break;
                }
                if($iv != ''){
                    $this->iv = hash('MD5', $iv, true);
                }else{
                    $this->iv = chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0); //IV is not set. It doesn't recommend.
                }
            }
            break;
            default:
                throw new \Exception('The key must be 8 bytes(64 bits), 16 bytes(128 bits), 24 bytes(192 bits) or 32 bytes(256 bits)!');
        }
        $this->bit = $bit;
    }

    public function encrypt($str) {
        $algorithm = $this->bit > 64 ? MCRYPT_RIJNDAEL_128 : 'des';
        //Open
        $module = mcrypt_module_open($algorithm, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($module, $this->key, $this->iv);

        //Padding
        $block = mcrypt_get_block_size($algorithm, MCRYPT_MODE_CBC); //Get Block Size
        $pad = $block - (strlen($str) % $block); //Compute how many characters need to pad
        $str .= str_repeat(chr($pad), $pad); // After pad, the str length must be equal to block or its integer multiples

        //Encrypt
        $encrypted = mcrypt_generic($module, $str);

        //Close
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);

        //Return
        return base64_encode($encrypted);
    }

    public function decrypt($str) {
        $algorithm = $this->bit > 64 ? MCRYPT_RIJNDAEL_128 : 'des';
        //Open 
        $module = mcrypt_module_open($algorithm, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($module, $this->key, $this->iv);

        //Decrypt
        $str = mdecrypt_generic($module, base64_decode($str)); //Get original str

        //Close
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);

        //Depadding
        $slast = ord(substr($str, -1)); //pad value and pad count
        $str = substr($str, 0, strlen($str) - $slast);

        //Return
        return $str;           
    }
    
    private static function crc64Table() {
        $crc64tab = [];
        $poly64rev = (0xC96C5795 << 32) | 0xD7870F42;
        for ($i = 0; $i < 256; ++$i) {
            for ($part = $i, $bit = 0; $bit < 8; ++$bit) {
                if ($part & 1) {
                    $part = (($part >> 1) & ~(0x8 << 60)) ^ $poly64rev;
                } else {
                    $part = ($part >> 1) & ~(0x8 << 60);
                }
            }
           $crc64tab[$i] = $part;
        }
        return $crc64tab;
    }
    
    private static function crc64($string) {
        static $crc64tab;
        if ($crc64tab === null) {
            $crc64tab = Tuling123Callback::crc64Table();
        }
        $h8Mask = ~(0xff << 56);
        $crc = 0;
        $length = strlen($string);
        for ($i = 0; $length; ++$i) {
            $crc = $crc64tab[($crc ^ ord($string[$i])) & 0xff] ^ (($crc >> 8) & $h8Mask);
        }
        
        return pack('CCCCCCCC', ($crc >> 56) & $h8Mask, (($crc << 8) >> 56) & $h8Mask, (($crc << 16) >> 56) & $h8Mask, (($crc << 24) >> 56) & $h8Mask, (($crc << 32) >> 56) & $h8Mask, (($crc << 40) >> 56) & $h8Mask, (($crc << 48) >> 56) & $h8Mask, (($crc << 56) >> 56) & $h8Mask);
    }
    
    public function httpPost($url,$data) {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_HEADER, 0);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curl, CURLOPT_URL, $url);
        $result = curl_exec($curl);
        curl_close($curl);
        return $result;
    }
    
}
    
?>