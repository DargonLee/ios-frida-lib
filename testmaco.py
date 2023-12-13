import frida
import sys


def on_message(message, data):
    print("[{}] => {}".format(message, data))


def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script(
        """
        const appWillFinishLaunching = ObjC.classes.NSApplicationDelegate['- applicationWillFinishLaunching:'];
        Interceptor.attach(appWillFinishLaunching.implementation, {
          onEnter(args) {
            // As this is an Objective-C method, the arguments are as follows:
            // 0. 'self'
            // 1. The selector (applicationWillFinishLaunching:)
            // 2. The first argument to this method
            const notification = new ObjC.Object(args[2]);

            // Convert it to a JS string and log it
            const notificationStr = notification.absoluteString().toString();
            console.log('Will finish launching with notification: ' + notificationStr);
          }
        });
    """
    )
    script.on("message", on_message)
    script.load()
    print("[!] Ctrl+D or Ctrl+Z to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == "__main__":
    main("Safari")
