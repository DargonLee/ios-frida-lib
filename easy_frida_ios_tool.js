/*
	* Example usage:
	* frida -U -f cn.hzs.mbs -l easy_frida_ios_tool.js --no-pause
	* frida -U -l frida.js --no-pause -f com.oeyes.moothook
	*/
var colors = {
	"resetColor": "\x1b[0m",
	"green": "\x1b[32m",
	"yellow": "\x1b[33m",
	"red": "\x1b[31m"
}

function UUHelp() {
	console.error("Usage: ")
	console.log('    Example usage: UUIntercept("+[VssCtrlSDK configMBSLoginInfo:]")')
	console.log('    Example usage: UUSearchClassAllMethods("VssCtrlSDK")')
	console.log('    Example usage: UUSearchClassesAllMethods(["VssCtrlSDK","VssClipboardManager"])')
	console.log('    Example usage: UUSearchClassesMethods(["VssCtrlSDK","VssClipboardManager"],["some methods"])')
	console.log('    Example usage: UUTrace("+[UULoadManger delayHandleMethod]");')
}

// UUIntercept - Begin
function _interceptPrintType(desc, arg) {
	try {
		console.log(desc + ObjC.Object(arg).$class + " " + ObjC.Object(arg).$className);
	} catch (err) {
		console.log(err)
	}
}

function _interceptPrintValue(desc, arg) {
	try {
		console.log(desc + ObjC.Object(arg));
	} catch (err) {
		console.log(desc + arg);
	}
}

function _interceptAuto(target) {
	var className = target.match(/^[-+]\[(.*)\s/)[1];
	var methodType = target.match(/^([-+])/)[1];
	var methodName = target.match(/^[-+]\[.*\s(.*)\]/)[1];
	var argCount = (methodName.match(/:/g) || []).length;
	console.log(colors.green, "\n[*] Info: trying to intercept.... ", target, colors.resetColor);
	var oldImpl = ObjC.classes[className][methodType + " " + methodName];
	Interceptor.attach(oldImpl.implementation, {

		onEnter: function(args) {
			console.warn("\n[+]Entered ->", target);
			for (var i = 0; i < argCount; i++) {
				_interceptPrintType("[-] arg " + (i + 1) + " type:\t", args[i + 2]);
				_interceptPrintValue("[-] arg " + (i + 1) + " value:\t", args[i + 2]);
			}
			console.log(colors.yellow, "\n[+]Backtrace.... ", target, colors.resetColor);
			console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
		},

		onLeave: function(retval) {
			console.warn("[+]Exiting ->", target);
			_interceptPrintType("[-] retval type:\t", retval);
			_interceptPrintValue("[-] retval value:\t", retval);

		}

	});
}
/*
	* Example usage:
	* 打印函数调用的所有参数值和类型
	* UUIntercept("+[VssCtrlSDK configMBSLoginInfo:]")
	*/
function UUIntercept(method) {
	if (ObjC.available) {
		_interceptAuto(method);
	} else {
		console.log("Not found: ", method);
	}
}
// UUIntercept - End


// UUAppInfo - Begin
function dictFromNSDictionary(nsDict) {
	var jsDict = {};
	var keys = nsDict.allKeys();
	var count = keys.count();
	for (var i = 0; i < count; i++) {
		var key = keys.objectAtIndex_(i);
		var value = nsDict.objectForKey_(key);
		jsDict[key.toString()] = value.toString();
	}

	return jsDict;
}

function arrayFromNSArray(nsArray) {
	var jsArray = [];
	var count = nsArray.count();
	for (var i = 0; i < count; i++) {
		jsArray[i] = nsArray.objectAtIndex_(i).toString();
	}
	return jsArray;
}

function infoDictionary() {
	if (ObjC.available && "NSBundle" in ObjC.classes) {
		var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
		return dictFromNSDictionary(info);
	}
	return null;
}

function infoLookup(key) {
	if (ObjC.available && "NSBundle" in ObjC.classes) {
		var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
		var value = info.objectForKey_(key);
		if (value === null) {
			return value;
		} else if (value.class().toString() === "__NSCFArray") {
			return arrayFromNSArray(value);
		} else if (value.class().toString() === "__NSCFDictionary") {
			return dictFromNSDictionary(value);
		} else {
			return value.toString();
		}
	}
	return null;
}

function UUAppStoreReceipt() {
	if (ObjC.available && "NSBundle" in ObjC.classes) {
		var info = ObjC.classes.NSBundle.mainBundle().appStoreReceiptURL();
		console.log(info.path());

		var data = ObjC.classes.NSData.dataWithContentsOfURL_(info);
		var fileExists = ObjC.classes.NSFileManager.defaultManager().fileExistsAtPath_(info.path());

		var dataResult = 'have data';
		var fileResult = 'file exists';

		if (data === null) {
			dataResult = 'null data';
		}
		if (fileExists === false) {
    		fileResult = "file not exists ";
		}		
		return fileResult  + 'and ' + dataResult;

		var string = data.base64EncodedStringWithOptions_(0);
		return string;
	}
}

function UULSApplicationWorkspace() {

	// 获取 LSApplicationWorkspace 类
	var LSApplicationWorkspace = ObjC.classes.LSApplicationWorkspace;

	// 获取 defaultWorkspace 方法并调用
	var workspace = LSApplicationWorkspace.defaultWorkspace();

	// 获取 installedPlugins 方法并调用
	var installedPlugins = workspace.installedPlugins();

	var pluginsCount = installedPlugins.count();

	console.log("installedPlugins:" + pluginsCount);

	// 遍历返回的数组
	for (var i = 0; i < pluginsCount; i++) {
		// 获取 LSPlugInKitProxy 对象
		var plugin = installedPlugins.objectAtIndex_(i);
		// 获取 containingBundle 方法并调用
		var containingBundle = plugin.containingBundle();
		if (containingBundle === null) { continue; }
		var bundleIdentifier = containingBundle.bundleIdentifier();
		if (bundleIdentifier.containsString_("com.apple")) { continue; }
		console.log("===========================>");
		console.log("bundleIdentifier ->", bundleIdentifier);
		console.log("applicationDSID ->", containingBundle.applicationDSID());
		console.log("applicationIdentifier ->", containingBundle.applicationIdentifier());
		console.log("applicationType ->", containingBundle.applicationType());
		console.log("dynamicDiskUsage ->", containingBundle.dynamicDiskUsage());
		console.log("itemID ->", containingBundle.itemID());
		console.log("itemName ->", containingBundle.itemName());
		console.log("minimumSystemVersion ->", containingBundle.minimumSystemVersion());
		console.log("requiredDeviceCapabilities ->", containingBundle.requiredDeviceCapabilities());
		console.log("sdkVersion ->", containingBundle.sdkVersion());
		console.log("shortVersionString ->", containingBundle.shortVersionString());
		console.log("sourceAppIdentifier ->", containingBundle.sourceAppIdentifier());
		console.log("staticDiskUsage ->", containingBundle.staticDiskUsage());
		console.log("teamID ->", containingBundle.teamID());
		console.log("vendorName ->", containingBundle.vendorName());
	}

}

function UUAppInfo() {
	var output = {};
	output["Name"] = infoLookup("CFBundleName");
	output["Bundle ID"] = ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
	output["Version"] = infoLookup("CFBundleVersion");
	output["Bundle"] = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
	output["Data"] = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString() + "/Documents";
	output["Binary"] = ObjC.classes.NSBundle.mainBundle().executablePath().toString();
	return output;
}
// UUAppInfo - End

function UUAPPGropuPath(groupId) {
	var url = ObjC.classes.NSFileManager.defaultManager().containerURLForSecurityApplicationGroupIdentifier_("group.com.jnit.ngpt");
	var path = ObjC.Object(url).absoluteString();
	return {
		"GroupID": path
	}
}


// UUSearchClass -Begin
function search_methods(className, search_method) {
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
	return methods_found;
}

function search_classes(search_class) {
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
	var n = 100;
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

function UUSearchClassAllMethods(searchClasse) {
	UUSearchClassesMethods([searchClasse], [])
}

function UUSearchClassesAllMethods(searchClasses) {
	UUSearchClassesMethods(searchClasses, [])
}

function UUSearchClassesMethods(searchClasses, searchMethods) {
	if (ObjC.available) {
		console.log(colors.green, "\n[*] Started: Hooking.... ", colors.resetColor);
		var classes_found = search_classes(searchClasses);
		for (var i = 0; i < classes_found.length; ++i) {
			var methods_found = 0;
			methods_found = search_methods(classes_found[i], searchMethods);

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
						console.log(colors.green, "[+] Detected call to: ", colors.resetColor);
						console.log('   ' + this._className + ' --> ' + this._methodName);
						console.log(colors.green, "[+] Dump Arugment in method: ", colors.resetColor);
						print_arguments(args);
						// console.log(ObjC.Object(args[2]));
						// var data = new ObjC.Object(args[2]);
						console.log(colors.green, "[+] Arugment type: ", colors.resetColor);
						// console.log(data.$className);
						/* Converting NSData to String */
						// var buf = data.bytes().readUtf8String(data.length());
						console.log(colors.green, "[+] NSData to String: ", colors.resetColor);
						// console.log(buf);
						/* Converting NSData to Binary Data */
						// var buf = data.bytes().readByteArray(data.length());
						console.log(colors.green, "[+] NSData to Binary Data: ", colors.resetColor);
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
// UUSearchClass -End


// UUFindClass -Begin
function UUFind_specific_method_in_all_classes(func_name) {
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

function UUFind_all_method_in_classe(class_name) {
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

// UUFindClass -End



// UUTrace -Begin
function UUTrace(pattern) {
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
				console.warn("\n[*] Entered " + name);

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
				console.warn("\n[*] Exiting " + name);
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

function printObjc(argument) {
    // 确保参数是 ObjC 对象
    if (argument === null || argument === undefined) {
        console.log("Argument is null or undefined");
        return;
    }

    var obj = new ObjC.Object(argument);
    
    // 获取对象的类名
    var className = obj.$className;
    console.log("[*] Object Class:", className);

    try {
        switch(className) {
            case "NSString":
                console.log("[*] String Value:", obj.UTF8String());
                break;
                
            case "NSData":
                var strValue = obj.bytes().readUtf8String(obj.length());
                console.log("[*] Data as String:", strValue);
                // 如果想要查看十六进制
                var hexString = "";
                var bytes = new Uint8Array(Memory.readByteArray(obj.bytes(), obj.length()));
                bytes.forEach(byte => hexString += ('0' + byte.toString(16)).slice(-2));
                console.log("[*] Data as Hex:", hexString);
                break;
                
            case "NSDictionary":
                console.log("[*] Dictionary Content:");
                var enumerator = obj.keyEnumerator();
                var key;
                while((key = enumerator.nextObject()) !== null) {
                    var value = obj.objectForKey_(key);
                    console.log(`   ${key} : ${value}`);
                    // 递归打印嵌套对象
                    if (value.$className === "NSDictionary" || 
                        value.$className === "NSArray" ||
                        value.$className === "NSData") {
                        console.log("   Nested object:");
                        printObjc(value);
                    }
                }
                break;
                
            case "NSArray":
                console.log("[*] Array Content:");
                var count = obj.count().valueOf();
                for (var i = 0; i < count; i++) {
                    var element = obj.objectAtIndex_(i);
                    console.log(`   [${i}] : ${element}`);
                    // 递归打印嵌套对象
                    if (element.$className === "NSDictionary" || 
                        element.$className === "NSArray" ||
                        element.$className === "NSData") {
                        console.log("   Nested object:");
                        printObjc(element);
                    }
                }
                break;
                
            case "NSNumber":
                console.log("[*] Number Value:", obj.doubleValue());
                break;
                
            case "NSDate":
                console.log("[*] Date Value:", obj.description());
                break;
                
            default:
                console.log("[*] Description:", obj.description());
                // 尝试调用常见方法
                if (obj.respondsToSelector_("UTF8String")) {
                    console.log("[*] UTF8String:", obj.UTF8String());
                }
        }
    } catch (error) {
        console.log("[!] Error printing object:", error);
    }
}

function dumpKeychain(argument) {

	var className = "Security";
	var hookMethods = ["SecItemAdd", "SecItemUpdate", "SecItemDelete"];

	for (var index = 0; index < hookMethods.length; index++) {
		var methodName = hookMethods[index];
		var ptr = null;
		Module.enumerateExports(className, {
			onMatch: function(imp) {
				if (imp.type == "function" && imp.name == methodName) {
					console.log("Found target method : " + methodName);

					try {
						Interceptor.attach(ptr(imp.address), {
							onEnter: function(args) {
								console.log("[+] Keychain operation: " + imp.name);
								var params = ObjC.Object(args[0]); // CFDictionaryRef => NSDictionary
								var keys = params.allKeys();
								for (index = 0; index < keys.count(); index++) {
									var k = keys.objectAtIndex_(index);
									var v = params.objectForKey_(k);
									if (k == "v_Data") {
										var string = ObjC.classes.NSString.alloc();
										v = string.initWithData_encoding_(v, 4).toString();
									}
									if (k == "pdmn") {
										if (v == "ak") {
											v = "kSecAttrAccessibleWhenUnlocked";
										} else if (v == "ck") {
											v = "kSecAttrAccessibleAfterFirstUnlock";
										} else if (v == "dk") {
											v = "kSecAttrAccessibleAlways";
										} else if (v == "aku") {
											v = "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
										} else if (v == "cku") {
											v = "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly";
										} else {
											// v == dku
											v = "kSecAttrAccessibleAlwaysThisDeviceOnly";
										}
									}
									console.log("\t-   " + k + "=" + v);
								}
							}
						});
					} catch (error) {
						console.log("Ignoring " + imp.name + ": " + error.message);
					}
				}
			},
			onComplete: function(e) {
				console.log("All methods loaded");
			}
		});
	}
}

// dumpKeychain();
// UUTrace("+[UULoadManger delayHandleMethod]");
// UUTrace("-[MBSSDK + login:completionHandler:]");
// UUTrace("*[CredManager *]");
// UUTrace("*[* *Password:*]");
// UUTrace("exports:libSystem.B.dylib!CCCrypt");
// UUTrace("exports:libSystem.B.dylib!open");
// UUTrace("exports:*!open*");
// usage examples
// UUTrace -End