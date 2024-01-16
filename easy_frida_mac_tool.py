import frida
import sys
import codecs


# 加载js文件
def _load_js_file(filename):
    with codecs.open(filename, "r", "utf-8") as f:
        source = f.read()
    return source

def on_message(message, data):
    print("[{}] => {}".format(message, data))


def main(target_process):
    session = frida.attach(target_process)
    script_source = _load_js_file("frida-mac/listprocess.js")
    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    print("[!] Ctrl+D or Ctrl+Z to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == "__main__":
    main("Safari")
