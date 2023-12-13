/*
	* raptor_frida_ios_*.js - Frida script snippets for iOS
	* Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
	*
	* Frida.re JS script snippets for iOS/ObjC instrumentation.
	* See https://www.frida.re/ and https://codeshare.frida.re/
	* for further information on this powerful tool.
	*
	* "We want to help others achieve interop through reverse
	* engineering" -- @oleavr
	*
	* Many thanks to Maurizio Agazzini <inode@wayreth.eu.org>
	* and Federico Dotta <federico.dotta@mediaservice.net>.
	*
	* Example usage:
	* # frida -U -f com.xxx.yyy -l raptor_frida_ios.js --no-pause
	*/

// print arg/ret type
function printType(desc, arg) {
	try {
		console.log(desc + ObjC.Object(arg).$class + " " + ObjC.Object(arg).$className);
	} catch (err) {
		console.log(err)
	}
}

// print arg/ret value
function printValue(desc, arg) {
	try {
		console.log(desc + ObjC.Object(arg));
	} catch (err) {
		console.log(desc + arg);
	}
}

// main interceptor
function autoIntercept(target) {
	var className = target.match(/^[-+]\[(.*)\s/)[1];
	var methodType = target.match(/^([-+])/)[1];
	var methodName = target.match(/^[-+]\[.*\s(.*)\]/)[1];
	var argCount = (methodName.match(/:/g) || []).length;

	console.log("\n[-]info: trying to intercept", target);
	var oldImpl = ObjC.classes[className][methodType + " " + methodName];

	Interceptor.attach(oldImpl.implementation, {

		onEnter: function(args) {
			console.log("\n[-] *** Entered", target, "***");
			for (var i = 0; i < argCount; i++) {
				printType("\n[-]arg " + (i + 1) + " type:\t", args[i + 2]);
				printValue("[-]arg " + (i + 1) + " value:\t", args[i + 2]);
			}
		},

		onLeave: function(retval) {
			printType("\n[-]retval type:\t", retval);
			printValue("[-]retval value:\t", retval);
			console.log("\n[-]*** Exiting", target, "***");
		}

	});
}

function Intercept(method) {
	if (ObjC.available) {
		autoIntercept(method);
	} else {
		console.log("error: Objective-C Runtime is not available!");
	}
}