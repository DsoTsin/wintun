[Wintun](https://github.com/WireGuard/wintun/tree/0.14.1) wrapper for Python 3
===

# Example

```python
import pywintunx_pmd3

def log(level: int, timestamp: Int64, message: str):
  pass

pywintunx_pmd3.set_logger(log)
pywintunx_pmd3.install_wetest_driver()
pywintunx_pmd3.uninstall_wetest_driver()

tun_dev = pywintunx_pmd3.TunTapDevice()
# Avaliable constructor include
# or TunTapDevice(name='XX')
# or TunTapDevice(name='XX', type='xxx')
# or TunTapDevice(name='XX', type='xxx', guid='xxxs')
# or TunTapDevice(name='XX', type='xxx', proto_aware=True)
# tundev.name, readonly property
tundev.ring_capacity = 8*1024*1024
tun_dev.mtu4 = 1460             # set ipv4 subinterface mtu
tun_dev.mtu = 1452              # set ipv6 subinterface mtu
tundev.addr4 = '10.2.3.4'       # set ipv4 subinterface address
tundev.addr = 'ffee:aadf:8877:2'# set ipv6 subinterface mtu
tundev.up()

packet = tundev.read() # receive a packet
tundev.wait_read_event()

tundev.write(b'\x00') # send a packet..

tundev.down()

...
tundev.close()

```
