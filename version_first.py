# airmon-ng check kill
# airmon-ng start wlan0

# нужно установить интерфейс в режим монитора
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, Dot11, Dot11Beacon, RadioTap

iface = "wlan0mon"
sender_mac = RandMAC() # генерируем рандомный MAC
ssid = "Test" # SSID задаем имя точки доступа, которую хотим создать
# создаем кадр 802.11
# type=0 -> фрейм управления
# subtype=8  -> этот кадр является рамкой маяка
# ddr1 -> MAC адрес получателя
# addr2 -> MAC отправителя      same
# addr3 -> MAC точки доступа    same

dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
beacon = Dot11Beacon()
# помещаем SSID во фрейм
essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
frame = RadioTap()/dot11/beacon/essid
sendp(frame, inter=0.1, iface=iface, loop=1)  # отправляем
