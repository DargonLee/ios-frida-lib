import sys
import threading
import frida
import codecs
import os

# 同步
FINISHED = threading.Event()
# 根目录
root_dir = os.path.dirname(os.path.realpath(__file__))
# js脚本目录
script_dir = os.path.join(root_dir, 'js/')
# App.js文件
APP_JS = os.path.join(script_dir, 'app.js')

# 获取第一个USB连接的设备
def get_usb_iphone():
    dManger = frida.get_device_manager()
    changed = threading.Event()
    def on_changed():
        changed.set()
    dManger.on("changed", on_changed)
    device = None
    while device is None:
        print(dManger.enumerate_devices())
        devices = [dev for dev in dManger.enumerate_devices() if dev.type == "usb"]
        if len(devices) == 0:
            print("✅ Writing for USB device...")
            changed.wait()
        else:
            #print("✅ 设备列表：\n{}".format(dManger.enumerate_devices()))
            device = devices[0]
    dManger.off("changed", on_changed)
    return device

# 列举手机的进程信息
def list_runing_process(device):
    processes = device.enumerate_processes()
    processes.sort(key = lambda item : item.pid)
    for process in processes:
        print('%-10s\t%s' % (str(process.pid), process.name))

# 列举手机的安装应用程序信息
def get_applications(device):
    try:
        applications = device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate applications: %s' % e)
    return applications
def list_applications(device):
    applications = get_applications(device)
    if len(applications) > 0:
        pid_column_width = max(map(lambda app: len('{}'.format(app.pid)), applications))
        name_column_width = max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        name_column_width = 0
        identifier_column_width = 0
    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-', name_column_width * '-', identifier_column_width * '-'))
    line_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    for application in sorted(applications, key=cmp_to_key(compare_applications)):
        if application.pid == 0:
            print(line_format % ('-', application.name, application.identifier))
        else:
            print(line_format % (application.pid, application.name, application.identifier))
def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""

    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K
def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name:
            return 1
        elif a.name < b.name:
            return -1
        else:
            return 0
    elif a_is_running:
        return -1
    else:
        return 1

# 从js接收消息
def deal_message_from_js(payload):
    # 基本信息输出
    if 'msg' in payload.keys():
        print("✅ {}".format(payload['msg']))
    # 安装app信息
    if 'app' in payload.keys():
        app = payload['app']
        print("✅ {}".format(app))
        for item in app:
            print("✅ {}".format(item))
    # 处理完成事件
    if 'finished' in payload.keys():
        FINISHED.set()
def on_message(message, data):
    if 'payload' in message:
        payload = message['payload']
        if isinstance(payload, dict):
            deal_message_from_js(payload)
        else:
            print('✅ js回传的信息不包含payload'.format(payload))
# 加载js文件
def load_js_file(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script

def main():
    # device = get_usb_iphone()
    # device = frida.get_device(id="a3037b06dc4e2af716484c9b85d2f93ba82a44c0")
    device = frida.get_usb_device()
    print("✅ 设备信息：{}".format(device))
    # print(APP_JS)
    # list_runing_process()

    # print("✅ 应用信息：")
    # list_applications(device)


    print("✅ 应用安装信息：\n")
    session = device.attach('SpringBoard')
    script = load_js_file(session, APP_JS)
    print(script.exports.add(2, 3))
    apps = script.exports.installed()
    for item in apps:
        data_path = '-'
        if len(item['dataPath']):
            data_path = item['dataPath']
        vsa_path = item['vsaPath']
        if vsa_path == "true":
            vsa_path = "沙箱App"
        else:
            vsa_path = ""
        print("✅ 【{}】<{}> {}\n{}\n{}\n{}".format(item['displayName'],item['bundleIdentifier'],vsa_path,item['bundlePath'],data_path,item['executablePath']))
    # script.post({'cmd': 'installed'})
    # script.post({'cmd': 'alert','title':'Hello','message':'world!!!'})
    FINISHED.wait()
    if session:
        session.detach()

if __name__ == "__main__":
    main()
