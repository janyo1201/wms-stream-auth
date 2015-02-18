wms-stream-auth
===============

Wowza stream auth module

Installation
------------

Application.xml <Modules> section

```xml
    <Module>
        <Name>ModuleAuth</Name>
        <Description>Stream auth by token</Description>
        <Class>com.streambox.wms.auth.module.ModuleAuth</Class>
    </Module>
```

Application.xml <Properties> section

```xml
    <Property>
        <Name>StreamAuthKey</Name>
        <Value>my_secret_key</Value>
    </Property>
```

PHP example

```php
    <?php
        function create_token(){
            $key = "my_secret_key";
            $time = time();
            $valid_minutes = 120;
            $hash = md5(sprintf("%s%s%s%s", $_SERVER['REMOTE_ADDR'], $key, $time, $valid_minutes));
            $params = sprintf("server_time=%s&hash_value=%s&validminutes=%s", $time, $hash, $valid_minutes);
            return base64_encode($params);
        }

        $secure_link = "rtmp://host:port/vod?wmsAuth=". create_token() ."/mp4:example.mp4";
    ?>
```