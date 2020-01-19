/**
 * miniui 插件
 *
 * 使用extend的方式，直接在jQuery增加新的方法
 *
 * author:chenlin
 * date:2019-11-12
 */
;(function($){

   $.extend({
        /**
         * grid的相关操作
         * */
        grid:{
            _options:{},
            /***
             * datagrid方法调用入口，
             * options:参数列表：
             *          grid：表示datagrid对象
             *          fromId：表示
             * */
            init:function(options){
                var defaults = {
                    gridId:"grid1",
                    formId:"",
                    queryParams:"",
                    autoLoad:false,
                    enterForLoad:true,
                    resetHeight:true,
                    modalTitle:"数据",
                    addUrl:"",
                    editUrl:"",
                    deleteUrl:""
                }
                this._options = $.extend(defaults,options);

                /** 判断是否需要自动加载数据*/
                if(this._options.autoLoad){
                    this.query();
                }
                /** 判断是否支持回车查询数据*/
                if(this._options.enterForLoad && this.hasForm()){
                    var _this = this;
                    $("#"+this._options.formId).keyup(function(event){
                        var code;

                        if (event.key !== undefined) {
                            code = event.key;
                        } else if (event.keyIdentifier !== undefined) {
                            code = event.keyIdentifier;
                        } else if (event.keyCode !== undefined) {
                            code = event.keyCode;
                        }
                        if(code == 13){
                            _this.query();
                        }
                    })
                }

                /** 重新设置datagrid的高度 */
                if(this._options.resetHeight){
                    var total = $(document).height();
                    var used = $(document.body).height();
                    this.getGrid().setHeight(total-used+50);
                }
            },
            /**表格查询方法*/
            query:function(){
                var g = this.getGrid();
                g.clearSelect();
                g.load(this.getQueryParams());

            },
            /**
             * 合并表单的查询参数和手动传入的查询参数
             * */
            getQueryParams:function(){
                var queryParams = {};
                if(this.hasForm()){
                    var form = this.getForm();
                    $.extend(queryParams,form.getData(true));
                }
                if(this._options.queryParams){
                    $.extend(queryParams,this._options.queryParams);
                }
                return queryParams;
            },
            /**
             * 获取datagrid对象
             * */
            getGrid:function(){
                return mini.get(this._options.gridId);
            },
            /**
             * 判断是否存在查询表单
             * */
            hasForm:function(){
                var b = false;
                if(this._options.formId){
                    b = true;
                }
                return b;
            },
            /**
             * 获取查询表单
             * */
            getForm:function(){
                return new mini.Form("#"+this._options.formId);
            }
        },
       btnClick:{
            /** 添加数据的方法 */
            add:function(width,height){
                var url = $.grid._options.addUrl;
                if($.common.isEmpty(url)){
                    mini.alert("添加数据的URL不能为空");
                    return false;
                }
                var title = "添加"+$.grid._options.modalTitle+"信息";
                var opts = {url:url,title:title};
                if(width){
                    opts.width=width;
                }
                if(height){
                    opts.height=height;
                }
                $.open(opts);
            },
            /** 编辑数据的方法，记录ID，通过grid来获取*/
            edit:function(width,height){
                var g = $.grid.getGrid();
                var rows = g.getSelecteds();
                if(rows.length == 1){
                    var url = $.grid._options.editUrl;
                    if($.common.isEmpty(url)){
                        mini.alert("添加数据的URL不能为空");
                        return false;
                    }
                    url.replace("{id}",rows[0].id);

                    var title = "编辑"+$.data._options.modalTitle+"信息";
                    var opts = {url:url,title:title};
                    if(width){
                        opts.width=width;
                    }
                    if(height){
                        opts.height=height;
                    }
                    $.open(opts);
                }else{
                    mini.alert("只能选择一条数据进行编辑");
                }
            },
            delete:function(){
                var g = $.grid.getGrid();
                var rows = g.getSelecteds();
                if(rows.length > 0){
                    var url = $.grid._options.deleteUrl;
                    if($.common.isEmpty(url)){
                        mini.alert("添加数据的URL不能为空");
                        return false;
                    }
                    mini.confirm("请您确定是否删除您所勾选中的记录","提示",function(action){
                        if(action =="ok" ){
                            var ids = [];
                            for (var i = 0;i < length;i++ )  {
                                ids.push(records[i].id);
                            }
                            var params = $.param({ids:ids,"_method":"DELETE"},true);
                            mf.ajaxPost({url:url,params:params},function (resp) {
                                mini.alert("操作成功","提示",function () {
                                   // doQuery();
                                    $.grid.query();
                                });
                            })
                        }
                    });
                }else{
                    mini.alert("请您选择您需要删除的记录");
                }
            }
       },

       form:{
           reset:function(formId){
                var f = new mini.Form("#"+formId);
                f.reset();
           }
       },

       /**
        * 弹窗方法
        * 需要传入的参数：
        *   url：必传
        *   title：必传
        *
        * */
       open:function(options){
            var defaults = {
                allowResize:false, //允许尺寸调节
                allowDrag:true,   //允许拖拽位置
                showMaxButton:true,   //显示最大化按钮
                width:800,
                height:400
            };

            var _options = $.extend(defaults,options);

            if($.common.isEmpty(_options.url)){
                mini.alert("弹窗URL不能为空","错误提示",function(){

                });
                return false;
            }
            var _this  = this;
            mini.open({
               url:this._options.url,
               title :this._options.title,
               width:this._options.width,
               height:this._options.height,
               showModal:true,
               allowResize:this._options.allowResize,       //允许尺寸调节
               allowDrag: this._options.allowDrag,         //允许拖拽位置
               showCloseButton: true,   //显示关闭按钮
               showMaxButton: this._options.showMaxButton,     //显示最大化按钮
               onload : function() {
                   var iframe = this.getIFrameEl();
                   if(options.showMax){
                       this.max();
                   }
                   if(options.data){
                       iframe.contentWindow.setData(options.data);
                   }
                   var tags = iframe.contentWindow.document.getElementsByTagName("INPUT");
                   if(!tags || tags.length == 0){
                       tags = iframe.contentWindow.document.getElementsByTagName("div");
                   }
                   if(!tags || tags.length == 0){
                       tags = iframe.contentWindow.document.getElementsByTagName("table");
                   }
                   $(tags[0]).focus();
               },
               ondestroy : function(action) {
                   if(_this._options.closeFun){
                       _this._options.closeFun(action,this);
                   }else{
                       if(action == "success"){
                           $.grid.query();
                       }
                   }
               }
           });
       },
       /**
        * 通用方法封装处理
        **/
       common: {
           /*** 判断字符串是否为空  */
           isEmpty: function (value) {
               if (value == null || this.trim(value) == "") {
                   return true;
               }
               return false;
           },
           /*** 判断一个字符串是否为非空串 */
           isNotEmpty: function (value) {
               return !$.common.isEmpty(value);
           },
           /*** 空对象转字符串 */
           nullToStr: function (value) {
               if ($.common.isEmpty(value)) {
                   return "-";
               }
               return value;
           },
           /** 是否显示数据 为空默认为显示 */
           visible: function (value) {
               if ($.common.isEmpty(value) || value == true) {
                   return true;
               }
               return false;
           },
           /*** 空格截取 */
           trim: function (value) {
               if (value == null) {
                   return "";
               }
               return value.toString().replace(/(^\s*)|(\s*$)|\r|\n/g, "");
           },
           /** 比较两个字符串（大小写敏感）**/
           equals: function (str, that) {
               return str == that;
           },
           /** 比较两个字符串（大小写不敏感）*/
           equalsIgnoreCase: function (str, that) {
               return String(str).toUpperCase() === String(that).toUpperCase();
           },
           /** 将字符串按指定字符分割 */
           split: function (str, sep, maxLen) {
               if ($.common.isEmpty(str)) {
                   return null;
               }
               var value = String(str).split(sep);
               return maxLen ? value.slice(0, maxLen - 1) : value;
           },
           /** 字符串格式化(%s ) */
           sprintf: function (str) {
               var args = arguments, flag = true, i = 1;
               str = str.replace(/%s/g, function () {
                   var arg = args[i++];
                   if (typeof arg === 'undefined') {
                       flag = false;
                       return '';
                   }
                   return arg;
               });
               return flag ? str : '';
           },
           /** 指定随机数返回 */
           random: function (min, max) {
               return Math.floor((Math.random() * max) + min);
           },
           /** 判断字符串是否是以start开头 */
           startWith: function (value, start) {
               var reg = new RegExp("^" + start);
               return reg.test(value)
           },
           /** 判断字符串是否是以end结尾 */
           endWith: function (value, end) {
               var reg = new RegExp(end + "$");
               return reg.test(value)
           },
           /** 数组去重 */
           uniqueFn: function (array) {
               var result = [];
               var hashObj = {};
               for (var i = 0; i < array.length; i++) {
                   if (!hashObj[array[i]]) {
                       hashObj[array[i]] = true;
                       result.push(array[i]);
                   }
               }
               return result;
           },
           /** 数组中的所有元素放入一个字符串 */
           join: function (array, separator) {
               if ($.common.isEmpty(array)) {
                   return null;
               }
               return array.join(separator);
           },
           /**获取form下所有的字段并转换为json对象 **/
           formToJSON: function (formId) {
               var json = {};
               $.each($("#" + formId).serializeArray(), function (i, field) {
                   json[field.name] = field.value;
               });
               return json;
           }
       }
   })

})(jQuery);

