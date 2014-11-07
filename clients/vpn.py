from tornado import ioloop
from ws4py.client.tornadoclient import TornadoWebSocketClient
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI
import sys


io_loop = ioloop.IOLoop.instance()

tap = TunTapDevice(flags=IFF_TAP|IFF_NO_PI, name='vpn-ws%d')
print tap.mtu

class VpnWSClient(TornadoWebSocketClient):

    def received_message(self, m):
        tap.write(str(m))

    def closed(self, code, reason=None):
        print "ooops"



ws = VpnWSClient(sys.argv[1])
ws.connect()

def tap_callback(fd, event):
    ws.send(tap.read(tap.mtu), binary=True)

io_loop.add_handler(tap.fileno(), tap_callback, io_loop.READ)
io_loop.start()
