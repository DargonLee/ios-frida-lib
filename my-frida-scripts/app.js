'use strict';

rpc.exports = {
	add(a, b) {
		return a + b;
	},
	sub(a, b) {
		return new Promise(resolve => {
			setTimeout(() => {
				resolve(a - b);
			}, 100);
		});
	},
	alert(title, message) {
		const UIAlertController = ObjC.classes.UIAlertController;
		const UIAlertAction = ObjC.classes.UIAlertAction;
		const UIApplication = ObjC.classes.UIApplication;

		// Defining a Block that will be passed as handler parameter to +[UIAlertAction actionWithTitle:style:handler:]
		var handler = new ObjC.Block({
			retType: 'void',
			argTypes: ['object'],
			implementation: function() {}
		});

		// Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
		ObjC.schedule(ObjC.mainQueue, function() {
			// Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
			var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(title, message, 1);
			// Again using integer numeral for style parameter that is enum
			var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
			alert.addAction_(defaultAction);
			// Instead of using `ObjC.choose()` and looking for UIViewController instances
			// on the heap, we have direct access through UIApplication:
			UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
		})
	},
	installed() {
		var ws = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
		var apps = ws.allInstalledApplications();
		var result = [];
		for (var i = 0; i < apps.count(); i++) {
			var proxy = apps.objectAtIndex_(i);
			var out = {};
			out["displayName"] = proxy.localizedName().toString();
			out["bundleIdentifier"] = proxy.bundleIdentifier().toString();
			out["bundlePath"] = proxy.bundleURL().toString();
			out["dataPath"] = [proxy.dataContainerURL(), ''].join('Documents');
			out["executablePath"] = [proxy.bundleURL().toString(), proxy.bundleExecutable().toString()].join('');

			out["vsaPath"] = "NO";
			const vsaPath = out["bundlePath"].slice(8) + 'emmlib.framework/emmlib';
			var mgr = ObjC.classes.NSFileManager.defaultManager();
			const isExitVsa = mgr.fileExistsAtPath_(vsaPath).toString();
			out["vsaPath"] = isExitVsa;


			result.push(out);
		}
		return result;
	}
};

function handleMessage(message) {
	const cmd = message['cmd'];
	if (cmd == 'installed') {

	}

	send({status: 'success'});
}

recv(handleMessage);