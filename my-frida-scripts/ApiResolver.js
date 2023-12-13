var resolver = new ApiResolver('objc');
resolver.enumerateMatches('*[NSFileManager *]', {
   onMatch: function(match) {
      console.log(match['name'] + ":" + match['address']);
      var method = match['name'];
      var implementation = match['address'];
 
      // 过滤需要拦截的方法
      if (//(method.indexOf("fileExistsAtPath") != -1) 
         (method.indexOf("removeItemAtPath") != -1)
        || (method.indexOf("moveItemAtPath") != -1)
        || (method.indexOf("copyItemAtPath") != -1)
        || (method.indexOf("createFileAtPath") != -1)
        || (method.indexOf("createDirectoryAtPath") != -1)
        || (method.indexOf("enumeratorAtPath") != -1)
        || (method.indexOf("contentsOfDirectoryAtPath") != -1)) {
 
         console.log(match['name'] + ":" + match['address']);
         try {
            Interceptor.attach(implementation, {
               onEnter: function(args) {
 
                  var className = ObjC.Object(args[0]);
                  var methodName = args[1];
                  var filePath = ObjC.Object(args[2]);
 
                  console.log("className: " + className.toString());
                  console.log("methodName: " + methodName.readUtf8String());
                  console.log("filePath: " + filePath.toString());
 
               },
               onLeave: function(retval) {
 
               }
            });
         } catch (err) {
            console.log("[!] Exception: " + err.message);
         }
      }
   },
   onComplete: function() {}
});