    var crypto  ;
    /***
     * 随机数生成算法。 len-生成结果的长度， radix-生成结果的组成，是二进制，十进制还是十六进制数。
     * */
    crypto.uuid = function (len, radix) {
        var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
        var uuid = [], i;
        radix = radix || chars.length;

        if (len) {
            // Compact form
            for (i = 0; i < len; i++) {
                uuid[i] = chars[0 | Math.random() * radix];
            }
        } else {
            // rfc4122, version 4 form
            var r;
            // rfc4122 requires these characters
            uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
            uuid[14] = '4';
            // Fill in random data.  At i==19 set the high bits of clock sequence as
            // per rfc4122, sec. 4.1.5
            for (i = 0; i < 36; i++) {
                if (!uuid[i]) {
                    r = 0 | Math.random() * 16;
                    uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
                }
            }
        }
        return uuid.join('');
    }

    /*
    * 加密函数
    * message - 明文数据
    * key - 密钥
    */
    crypto.encryptData = function (message, key) {
        var keyHex = CryptoJS.enc.Utf8.parse(key);
        var iv = CryptoJS.enc.Utf8.parse(key.substr(0, 16));
        var srcs = CryptoJS.enc.Utf8.parse(message);
        var encrypted = CryptoJS.AES.encrypt(srcs, keyHex, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString();
    }

    /*
     * 解密函数
     * ciphertext - 要解密的密文。
     * key ：密钥信息
    */
    crypto.decryptData = function (ciphertext, key) {
        var keyHex = CryptoJS.enc.Utf8.parse(key);
        var iv = CryptoJS.enc.Utf8.parse(key.substr(0, 16));
        var decrypt = CryptoJS.AES.decrypt(ciphertext, keyHex, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return CryptoJS.enc.Utf8.stringify(decrypt).toString();
    }

    /**
     *
     * @param url 请求地址
     * @param params 待加密的参数
     * @param skipParams 跳过加密的参数
     * @param rsaModulus rsa公钥的模
     * @param rsaExponent rsa公钥的指数
     * @param successFun 执行成功的方法
     * @param errorFun 失败的方法
     */
    crypto.ajaxPost = function (url, params, skipParams, rsaModulus, rsaExponent, successFun, errorFun) {
        /** aes 密钥*/
        var aesKey = crypto.uuid(32, 16);
        /** 先把对象转成字符串，然后aes加密*/
        var encrypt = crypto.encryptData(JSON.stringify(params), aesKey);
        //1024位就是130，2048位就是260.。。。。

        setMaxDigits(130);
        var encryptdRsaKey = new RSAKeyPair(rsaExponent, "", rsaModulus);

        /* 组合参数 */
        var param = {
            _encryptData: encrypt,
            _key: encryptedString(encryptdRsaKey, encodeURIComponent(aesKey)),
            _flag: "1"
        };
        //console.log("加密参数：%o",param);
        /* 合并参数*/
        if (skipParams) {
            $.extend(param, skipParams);
        }
        //console.log("合并所有参数：%o",param);
        $.post(url, param, function (data) {
            if (data.success) {
                /*返回值中有encryptData和key两个参数，并且不能为空*/
                if (data.encryptData && data.key) {
                    var decryptdRsaKey = new RSAKeyPair("", rsaExponent, rsaModulus);

                    var aesKey = decodeURIComponent(crypto.reverse(decryptedString(decryptdRsaKey, data.key)));
                    data.encryptData = crypto.decryptData(decodeURIComponent(data.encryptData), aesKey);
                } else {

                }
                if (successFun) {
                    successFun(data);
                }

            } else {
                if (errorFun) {
                    errorFun(data);
                } else {
                    if (data.message) {
                        alert(data.message);
                    } else {
                        alert("操作失败,请您检查是否输入有误...");
                    }
                }
            }
        }, "json");
    }

    crypto.ajaxPostByJosn = function (url, params, skipParams, rsaModulus, rsaExponent, successFun, errorFun) {
        /** aes 密钥*/
        var aesKey = crypto.uuid(32, 16);
        /** 先把对象转成字符串，然后aes加密*/
        var encrypt = crypto.encryptData(JSON.stringify(params), aesKey);
        //1024位就是130，2048位就是260.。。。。

        setMaxDigits(130);
        var encryptdRsaKey = new RSAKeyPair(rsaExponent, "", rsaModulus);

        /* 组合参数 */
        var param = {
            encryptData: encrypt,
            encryptKey: encryptedString(encryptdRsaKey, encodeURIComponent(aesKey)),
            encryptFlag: "1"
        };
        //console.log("加密参数：%o",param);
        /* 合并参数*/
        if (skipParams) {
            $.extend(param, skipParams);
        }
        console.log("合并所有参数：%o",param);
        $.ajax({
            url:url,
            type:"POST",
            contentType:"application/json;charset=utf-8",
            data:JSON.stringify(param),
            dataType:"json",
            success:function(data, textStatus, jqXHR){
                if (data.success) {
                    /*返回值中有encryptData和key两个参数，并且不能为空*/
                    if (data.encryptData && data.key) {
                        var decryptdRsaKey = new RSAKeyPair("", rsaExponent, rsaModulus);

                        var aesKey = decodeURIComponent(crypto.reverse(decryptedString(decryptdRsaKey, data.key)));
                        data.encryptData = crypto.decryptData(decodeURIComponent(data.encryptData), aesKey);
                    } else {

                    }
                    if (successFun) {
                        successFun(data);
                    }

                } else {
                    if (errorFun) {
                        errorFun(data);
                    } else {
                        if (data.message) {
                            alert(data.message);
                        } else {
                            alert("操作失败,请您检查是否输入有误...");
                        }
                    }
                }
            },
            error:function (XMLHttpRequest, textStatus, errorThrown){
                var message = textStatus;
                if(errorThrown){
                    message = message;
                }
                alert("AJAX 调用失败,原因:"+message);
            }
        });
    }


    crypto.reverse = function (str) {
        return str.split("").reverse().join("");
    }
