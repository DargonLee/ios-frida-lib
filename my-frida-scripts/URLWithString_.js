var className = "NSURL";
var funcName = "+ URLWithString:";
var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
Interceptor.attach(hook.implementation, {
    onLeave: function(retval) {
 
        console.log("[*] Class Name: " + className);
        console.log("[*] Method Name: " + funcName);
        console.log("\t[-] Type of return value: " + typeof retval);
        console.log("\t[-] Original Return Value: " + retval);
    },
 
    onEnter: function(args){
 
        var className = ObjC.Object(args[0]);
        var methodName = args[1];
        var urlString = ObjC.Object(args[2]);
 
        var file = new File("/var/mobile/log.txt","a+");//a+表示追加内容，和c语言的fopen函数模式类似
        console.log("className: " + className.toString());
        console.log("methodName: " + methodName.readUtf8String());
        console.log("urlString: " + urlString.toString());
        console.log("-----------------------------------------");
 
        urlString = ObjC.classes.NSString.stringWithString_("http://www.baidu.com")
        console.log("newUrlString: " + urlString.toString());
        console.log("-----------------------------------------");

		file.write("className: " + className.toString());
		file.write("methodName: " + methodName.readUtf8String());
        file.write("urlString: " + urlString.toString());
        file.write("-----------------------------------------")

		file.flush();
		file.close();
    }
});