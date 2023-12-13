/*
Description: 
Hooks into methods
* Given one or more classes in "search_class", it hooks into all their methods.
* Given one or more methods in "search_method", it hooks into all methods of any classes that meet with the search criteria.
* Given a class and a method, it hooks into the method of this class.
* Neither class nor method full name is needed in order to hook. If a partial string is given, the script will hook into all the methods that have the string in their name.
*/
// Usage: frida  -U -l frida.js  --no-pause -f com.oeyes.moothook
// var search_class = ['UUMbsSDKManager', 'UUAppPolicyTaskHandle', 'UULoginTaskHandle', 'UUDispenseRequestTask', 'UULoadManger'];
// var search_method = ['+ initialization:', '- requestAppPolicy', '- mbs_handleLoginSuccessResultWith:', '- handleLoginFailureResultWith:', '- loginWithAccountName:pwd:serverUrl:companyCode:loginType:success:failure:', '- handleFailureResultWith:', '+ delayHandleMethod'];
var search_class = ['UUMBSRequestedTask'];
var search_method = ['+ loginWithAccountName:password:loginType:success:failure:'];
// var search_class = [];
// var search_method = [];

var colors = {
    "resetColor": "\x1b[0m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "red": "\x1b[31m"
}

function search_methods(className) {
    // console.log(colors.green,"\n[*] Started: search_methods....",colors.resetColor);
    var methods_found = [];
    var methods = ObjC.classes[className].$ownMethods;
    if (Array.isArray(search_method) && search_method.length) { //search_method not empty
        for (var j = 0; j < search_method.length; j++) {
            if (methods.join(' ').toLowerCase().includes(search_method[j].toLowerCase())) {
                for (var i = 0; i < methods.length; i++) {
                    if (methods[i].toLowerCase().includes(search_method[j].toLowerCase())) {
                        methods_found.push(methods[i]);
                    }
                }
            }
        }
    } else {
        var methods = ObjC.classes[className].$ownMethods;
        for (var i = 0; i < methods.length; i++) {
            methods_found.push(methods[i]);
        }
    }
    // console.log(methods_found);
    return methods_found;
}

function search_classes() {
    // console.log(colors.green,"\n[*] Started: search_classes.... ",colors.resetColor);
    var classes_found = [];
    for (var className in ObjC.classes) {
        if (Array.isArray(search_class) && search_class.length) {
            for (var i = 0; i < search_class.length; i++) {
                if (className.toLowerCase().includes(search_class[i].toLowerCase())) {
                    classes_found.push(className);
                }
            }
        }
    }
    // console.log(classes_found);
    return classes_found;
}

function print_arguments(args) {
    /*
    Frida's Interceptor has no information about the number of arguments, because there is no such 
    information available at the ABI level (and we don't rely on debug symbols).

    I have implemented this function in order to try to determine how many arguments a method is using.
    It stops when:
        - The object is not nil
        - The argument is not the same as the one before    
     */
    var n = 15;
    var last_arg = '';
    for (var i = 2; i < n; ++i) {
        var arg = (new ObjC.Object(args[i])).toString();
        if (arg == 'nil' || arg == last_arg) {
            break;
        }
        last_arg = arg;
        console.log('\t[-] arg' + i + ': ' + (new ObjC.Object(args[i])).toString());
    }
}

function traceClassesAndMethods() {
    if (ObjC.available) {
        console.log(colors.green, "\n[*] Started: Hooking.... ", colors.resetColor);
        var classes_found = search_classes();
        for (var i = 0; i < classes_found.length; ++i) {
            var methods_found = 0;
            methods_found = search_methods(classes_found[i]);

            if (Object.keys(methods_found).length) {
                console.log(classes_found[i]);
            }
            for (var j = 0; j < methods_found.length; ++j) {
                var _className = "" + classes_found[i];
                var _methodName = "" + methods_found[j];
                var hooking = ObjC.classes[_className][_methodName];
                console.log('   ' + methods_found[j]);

                Interceptor.attach(hooking.implementation, {
                    onEnter: function(args) {
                        this._className = ObjC.Object(args[0]).toString();
                        this._methodName = ObjC.selectorAsString(args[1]);
                        console.log(colors.green, "\n[+] Detected call to: ", colors.resetColor);
                        console.log('   ' + this._className + ' --> ' + this._methodName);
                        console.log(colors.green, "[+] Dump Arugment in method: ", colors.resetColor);
                        print_arguments(args);
                        // console.log(ObjC.Object(args[2]).toString());
                        // console.log(ObjC.Object(args[3]));
                        // if (this._className === 'UUDispenseRequestTask') {
                        //     console.log(ObjC.Object(args[3]).toString());
                        //     console.log(ObjC.Object(args[4]).toString());
                        // }

                        // console.log(colors.green,"[+] Arugment type: ",colors.resetColor);
                        // var data = new ObjC.Object(args[2]);
                        // console.log(data.$className);
                        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
                        console.warn("\n[-] ======== Backtrace Start  ========");
                        console.log(backtrace);
                        console.warn("\n[-] ======== Backtrace End  ========");
                        /* Converting NSData to String */
                        // var buf = data.bytes().readUtf8String(data.length());
                        // console.log(colors.green,"[+] NSData to String: ",colors.resetColor);
                        // console.log(buf);
                        /* Converting NSData to Binary Data */
                        // var buf = data.bytes().readByteArray(data.length());
                        // console.log(colors.green,"[+] NSData to Binary Data: ",colors.resetColor);
                        // console.log(hexdump(buf, { ansi: true }));

                    },
                    onLeave: function(returnValues) {
                        console.log(colors.green, "Return value of: ", colors.resetColor);
                        console.log('   ' + this._className + ' --> ' + this._methodName);
                        console.log(colors.green, "\t[-] Type of return value: ", colors.resetColor + Object.prototype.toString.call(returnValues));
                        console.log(colors.green, "\t[-] Return Value: ", colors.resetColor + returnValues);
                    }
                });
            }

        }
        console.log('\n[*] Starting Intercepting');
    } else {
        console.log('Objective-C Runtime is not available!');
    }
}


function run_find_specific_method_in_all_classes(func_name) {
    console.log("[*] Started: Find Specific Method in All Classes");
    for (var className in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(className)) {
            //var methods = ObjC.classes[className].$methods;
            var methods = ObjC.classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++) {
                if (methods[i].includes(func_name)) {
                    console.log("[+] Class: " + className);
                    console.log("\t[-] Method: " + methods[i]);
                    console.log("\t\t[-] Arguments Type: " + ObjC.classes[className][methods[i]].argumentTypes);
                    console.log("\t\t[-] Return Type: " + ObjC.classes[className][methods[i]].returnType);
                }
            }
        }
    }
    console.log("[*] Completed: Find Specific Method in All Classes");
}

function find_specific_method_in_all_classes(func_name) {
    setImmediate(run_find_specific_method_in_all_classes, [func_name])
}

function find_all_method_in_classe(class_name) {
    console.log("[*] Started: Find All Methods of Classe")
    for (var className in ObjC.classes) {
        if (className === class_name) {
            console.warn("[+] Class: " + className);
            //var methods = ObjC.classes[className].$methods;
            var methods = ObjC.classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++) {
                console.log(colors.green, "\t[-] Method: ", methods[i], colors.resetColor);
                try {
                    console.log("\t\t[-] Arguments Type: " + ObjC.classes[className][methods[i]].argumentTypes);
                    console.log("\t\t[-] Return Type: " + ObjC.classes[className][methods[i]].returnType);
                } catch (err) {}
            }
            break;
        }
    }
    console.log("[*] Completed: Find Methods of All Classes")
}

//Your function name goes here
// find_specific_method_in_all_classes("function_name_here")


// generic trace
function trace(pattern) {
    var type = (pattern.indexOf(" ") === -1) ? "module" : "objc";
    var res = new ApiResolver(type);
    var matches = res.enumerateMatchesSync(pattern);
    var targets = uniqBy(matches, JSON.stringify);

    targets.forEach(function(target) {
        if (type === "objc")
            traceObjC(target.address, target.name);
        else if (type === "module")
            traceModule(target.address, target.name);
    });
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function(item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

// trace ObjC methods
function traceObjC(impl, name) {
    console.log("Tracing " + name);

    Interceptor.attach(impl, {

        onEnter: function(args) {

            // debug only the intended calls
            this.flag = 0;
            // if (ObjC.Object(args[2]).toString() === "1234567890abcdef1234567890abcdef12345678")
            this.flag = 1;

            if (this.flag) {
                console.warn("\n*** entered " + name);

                // print full backtrace
                // console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                //      .map(DebugSymbol.fromAddress).join("\n"));

                // print caller
                console.log("\nCaller: " + DebugSymbol.fromAddress(this.returnAddress));

                // print args
                if (name.indexOf(":") !== -1) {
                    console.log();
                    var par = name.split(":");
                    par[0] = par[0].split(" ")[1];
                    for (var i = 0; i < par.length - 1; i++)
                        printArg(par[i] + ": ", args[i + 2]);
                }
            }
        },

        onLeave: function(retval) {

            if (this.flag) {
                // print retval
                printArg("\nretval: ", retval);
                console.warn("\n*** exiting " + name);
            }
        }

    });
}

// trace Module functions
function traceModule(impl, name) {
    console.log("Tracing " + name);

    Interceptor.attach(impl, {

        onEnter: function(args) {

            // debug only the intended calls
            this.flag = 0;
            // var filename = Memory.readCString(ptr(args[0]));
            // if (filename.indexOf("Bundle") === -1 && filename.indexOf("Cache") === -1) // exclusion list
            // if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
            this.flag = 1;

            if (this.flag) {
                console.warn("\n*** entered " + name);

                console.warn("\n\targs " + args);

                // print backtrace
                console.log("\n\tBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n"));
            }
        },

        onLeave: function(retval) {

            if (this.flag) {
                // print retval
                printArg("\n\tretval: ", retval);
                console.warn("\n*** exiting " + name);
            }
        }

    });
}

// print helper
function printArg(desc, arg) {
    try {
        console.log(desc + ObjC.Object(arg));
    } catch (err) {
        console.log(desc + arg);
    }
}
trace("-[AppDelegate openPermissionsAction:launchOptions:]");
// trace("-[MBSSDK + login:completionHandler:]");
// trace("*[CredManager *]");
// trace("*[* *Password:*]");
// trace("exports:libSystem.B.dylib!CCCrypt");
// trace("exports:libSystem.B.dylib!open");
// trace("exports:*!open*");
// usage examples

/*
var obj = new ObjC.Object(ptr(args[2]));
console.log(obj['- _ivarDescription]().toString());
*/

function observeClass(name) {
    var k = ObjC.classes[name];
    k.$ownMethods.forEach(function(m) {
        var impl = k[m].implementation;
        // console.log('Observing ' + name + ' ' + m);
        console.log(colors.green, "\n[*] Started: Observing.... \n\t", colors.resetColor + name + ' ' + m);
        Interceptor.attach(impl, {
            onEnter: function(a) {
                this.log = [];
                this.log.push('(' + a[0] + ',' + Memory.readUtf8String(a[1]) + ') ' + name + ' ' + m);
                if (m.indexOf(':') !== -1) {
                    var params = m.split(':');
                    params[0] = params[0].split(' ')[1];
                    for (var i = 0; i < params.length - 1; i++) {
                        try {
                            this.log.push(params[i] + ': ' + new ObjC.Object(a[2 + i]).toString());
                        } catch (e) {
                            this.log.push(params[i] + ': ' + a[2 + i].toString());
                        }
                    }
                }

                this.log.push(
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .join('\n')
                );
            },

            onLeave: function(r) {
                try {
                    this.log.push('RET: ' + new ObjC.Object(r).toString());
                } catch (e) {
                    this.log.push('RET: ' + r.toString());
                }

                console.log(this.log.join('\n') + '\n');
            }
        });
    });
}
