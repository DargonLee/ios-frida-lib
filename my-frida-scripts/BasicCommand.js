var invalidParamStr = 'Invalid parameter';
var missingParamStr = 'Missing parameter';
function AppId() {
    [NSBundle mainBundle].bundleIdentifier;
}
function AppPath() { 
    [NSBundle mainBundle].bundlePath;
}
function DocPath() {
    NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
}
function CachesPath() {
    return NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES)[0];
}
function LoadFramework(name) {
    var head = "/System/Library/";
    var foot = "Frameworks/" + name + ".framework";
    var bundle = [NSBundle bundleWithPath: head + foot] || [NSBundle bundleWithPath: head + "Private" + foot];
    [bundle load];
    return bundle;
}
function KeyWindow() {
    return UIApp.keyWindow;
}
function RootVc() {
    return UIApp.keyWindow.rootViewController;
}
function _UUFrontVc(vc) {
    if (vc.presentedViewController) {
        return _UUFrontVc(vc.presentedViewController);
    } else if ([vc isKindOfClass: [UITabBarController class]]) {
        return _UUFrontVc(vc.selectedViewController);
    } else if ([vc isKindOfClass: [UINavigationController class]]) {
        return _UUFrontVc(vc.visibleViewController);
    } else {
        var count = vc.childViewControllers.count;
        for (var i = count - 1; i >= 0; i--) {
            var childVc = vc.childViewControllers[i];
            if (childVc && childVc.view.window) {
                vc = _UUFrontVc(childVc);
                break;
            }
        }
        return vc;
    }
}
function FrontVc() {
    return _UUFrontVc(UIApp.keyWindow.rootViewController);
}
function VcSubviews(vc) {
    if (![vc isKindOfClass: [UIViewController class]]) throw new Error(invalidParamStr);
    return vc.view.recursiveDescription().toString();
}
function FrontVcSubViews() {
    return UUVcSubviews(_UUFrontVc(UIApp.keyWindow.rootViewController));
}
function BtnTouchUpEvent(btn) {
    var events = [];
    var allTargets = btn.allTargets().allObjects()
    var count = allTargets.count;
    for (var i = count - 1; i >= 0; i--) {
        if (btn != allTargets[i]) {
            var e = [btn actionsForTarget: allTargets[i] forControlEvent: UIControlEventTouchUpInside];
            events.push(e);
        }
    }
    return events;
}
function PointMake(x, y) {
    return {
        0: x,
        1: y
    }
}
function SizeMake(w, h) {
    return {
        0: w,
        1: h
    };
};
function RectMake(x, y, w, h) {
    return {
        0: UUPointMake(x, y),
        1: UUSizeMake(w, h)
    };
}
function ChildVcs(vc) {
    if (![vc isKindOfClass: [UIViewController class]]) throw new Error(invalidParamStr);
    return [vc _printHierarchy].toString();
}
function Subviews(view) {
    if (![view isKindOfClass: [UIView class]]) throw new Error(invalidParamStr);
    return view.recursiveDescription().toString();
}
function IsString(str) {
    return typeof str == 'string' || str instanceof String;
}
function IsArray(arr) {
    return arr instanceof Array;
}
function IsNumber(num) {
    return typeof num == 'number' || num instanceof Number;
}
function _UUClass(className) {
    if (!className) throw new Error(missingParamStr);
    if (UUIsString(className)) {
        return NSClassFromString(className);
    }
    if (!className) throw new Error(invalidParamStr);
    // 对象或者类
    return className.class();
}
function Subclasses(className, reg) {
    className = _UUClass(className);

    return [c
        for each(c in ObjectiveC.classes)
        if (c != className &&
            class_getSuperclass(c) &&
            [c isSubclassOfClass: className] &&
            (!reg || reg.test(c)))
    ];
}
function _UUGetMethods(className, reg, clazz) {
    className = _UUClass(className);

    var count = new new Type('I');
    var classObj = clazz ? className.constructor : className;
    var methodList = class_copyMethodList(classObj, count);
    var methodsArray = [];
    var methodNamesArray = [];
    for (var i = 0; i < * count; i++) {
        var method = methodList[i];
        var selector = method_getName(method);
        var name = sel_getName(selector);
        if (reg && !reg.test(name)) continue;
        methodsArray.push({
            selector: selector,
            type: method_getTypeEncoding(method)
        });
        methodNamesArray.push(name);
    }
    free(methodList);
    return [methodsArray, methodNamesArray];
}
function _UUMethods(className, reg, clazz) {
    return _UUGetMethods(className, reg, clazz)[0];
}

function _UUMethodNames(className, reg, clazz) {
    return _UUGetMethods(className, reg, clazz)[1];
}
function InstanceMethods(className, reg) {
    return _UUMethods(className, reg);
}
function InstanceMethodNames(className, reg) {
    return _UUMethodNames(className, reg);
}
function ClassMethods(className, reg) {
    return _UUMethods(className, reg, true);
}

function ClassMethodNames(className, reg) {
    return _UUMethodNames(className, reg, true);
}

function Ivars(obj, reg) {
    if (!obj) throw new Error(missingParamStr);
    var x = {};
    for (var i in * obj) {
        try {
            var value = ( * obj)[i];
            if (reg && !reg.test(i) && !reg.test(value)) continue;
            x[i] = value;
        } catch (e) {}
    }
    return x;
}
function IvarNames(obj, reg) {
    if (!obj) throw new Error(missingParamStr);
    var array = [];
    for (var name in * obj) {
        if (reg && !reg.test(name)) continue;
        array.push(name);
    }
    return array;
}