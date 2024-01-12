[Wintun](https://github.com/WireGuard/wintun/tree/0.14.1) wrapper for Python 3
===

# Example

```python
import pywintun_pmd3

def log(level: int, timestamp: Int64, message: str):
  pass

pywintun_pmd3.set_logger(log)
pywintun_pmd3.install_wetest_driver()

tun_dev = pywintun_pmd3.TunTapDevice()
# Avaliable constructor include
# or TunTapDevice(name='XX')
# or TunTapDevice(name='XX')
# tundev.name, readonly property
tundev.ring_capacity = 8*1024*1024
tun_dev.mtu = 1452
tundev.addr = '10.2.3.4'
# tundev.addr = 'ffee:aadf:8877:2'
tundev.up()

packet = tundev.read() # receive a packet
tundev.wait_read_event()

tundev.write(b'\x00') # send a packet..

tundev.down()

...
tundev.close()

```
