;common = {
    isJson : function (string){
        return !!(typeof (string) == "string" && string.match("^\{(.+:.+,*){1,}\}$"));
    }
};
