//获取沙盒目录
function getHomeDir(){
    var NSHomeDirectory = new NativeFunction(ptr(Module.findExportByName("Foundation", "NSHomeDirectory")), 'pointer', []);
    var path = new ObjC.Object(NSHomeDirectory());
    console.log('homeDir: ' + path);
    return path;
}
 
//获取App目录
function getAppDir(){
  var bundle = ObjC.classes.NSBundle;
  var mainBundle = bundle.mainBundle();
        var appDir =  mainBundle.bundlePath();
        console.log('appDir: ' + appDir);
        return appDir;
}
 
getHomeDir();
getAppDir();