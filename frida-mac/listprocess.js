printClasses: function () {
    var classes = ObjC.classes;
    for (var i = 0; i < classes.length; i++) {
      console.log(classes[i].toString());
    }
  }


const appWillFinishLaunching =
      ObjC.classes.NSApplicationDelegate["- applicationWillFinishLaunching:"];
    Interceptor.attach(appWillFinishLaunching.implementation, {
      onEnter(args) {
        // As this is an Objective-C method, the argument s are as follows:
        // 0. 'self'
        // 1. The selector (applicationWillFinishLaunching:)
        // 2. The first argument to this method
        const notification = new ObjC.Object(args[2]);

        // Convert it to a JS string and log it
        const notificationStr = notification.absoluteString().toString();
        console.log(
          "Will finish launching with notification: " + notificationStr
        );
      },
    });
