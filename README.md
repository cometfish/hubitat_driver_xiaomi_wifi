# Xiaomi WiFi driver

Hubitat Driver for controlling Xiaomi WiFi devices locally, with no hub or cloud connection required.

Tested on _chuangmi.plug.m1_ only.

Note: Unfortunately the plug eventually stops responding to commands until you physically cycle the power to it. Others are reporting this issue too, so it appears to be a fault with the plug itself, not this driver: https://xiaomi.eu/community/threads/mi-plug-mini-socket-wifi-communication-problems.47985/

1. Add `plug_m1.groovy` to your Hubitat as a new Driver (under `Drivers Code`)
2. Add a new device for your WiFi Socket to your Hubitat, set device Type to your User driver of 'Xiaomi WiFi Socket'
3. Assign your plug a static IP, and enter the IP into the device's `IP Address` setting in Hubitat.
4. (Optional) If your device is linked to the Mi Cloud, it may be hiding its device token from all other requests, including this driver - if so, manually enter the token into the `Device Token` setting in Hubitat. Try the options here to obtain your token if you don't already know it - otherwise you may need to reset the device: https://github.com/jghaanstra/com.xiaomi-miio/blob/master/docs/obtain_token.md
5. Pressing Refresh on the device in Hubitat should now load the current switch state (on/off) and the temperature reading. Enjoy :)

References:  
Mi Home Binary Protocol: https://github.com/OpenMiHome/mihome-binary-protocol  
Working protocol example: https://github.com/aholstenson/miio
