/*
 * Xiaomi WiFi Socket driver (chuangmi.plug.m1)
 *
 * Controls the original Xiaomi WiFi socket directly via local commands (no hub or cloud needed)
 * 
 */

metadata {
    definition(name: "Xiaomi WiFi Socket", namespace: "community", author: "cometfish") {
        capability "Actuator"
        capability "Switch"
        capability "Sensor"
		capability "Outlet"
		//capability "TemperatureMeasurement"
		
		//attribute "temperature", "number"
		attribute "switch", "enum", ["off", "on"] 
		
		command "on" 
		command "off"
		
		command "refresh"
    }
}

preferences {
    section("URIs") {
        input "ipAddress", "text", title: "IP Address", required: true
		input "token", "text", title: "Device Token (optional if device is uninitialised)", required: false
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: true
    }
}

import java.security.MessageDigest
import javax.crypto.spec.IvParameterSpec 
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher

def updated() {
	if (settings.token!="") {
		state.token = settings.token
	} 
}
def refresh() {
	connect(tokenResponseStatus)
}
def sendMsgStatus(rdeviceID, rtoken, rstamp) {
	sendMsg('{"id": 1, "method": "get_prop", "params": ["power", "temperature"]}', rdeviceID, rtoken, rstamp)
}
def on() {
	connect(tokenResponseOn)
}
def sendMsgOn(rdeviceID, rtoken, rstamp) {
	
	sendMsg('{"id": 2, "method": "set_power", "params": ["on"]}', rdeviceID, rtoken, rstamp) 
}
def off() {
	connect(tokenResponseOff)
}
def sendMsgOff(rdeviceID, rtoken, rstamp) {
	sendMsg('{"id": 3, "method": "set_power", "params": ["off"]}', rdeviceID, rtoken, rstamp)
}

def parse(String description) {
	log.info parseLanMessage(description).payload
}
def tokenResponseStatus(String description) {
	tokenResponse(description, "status")			
}
def tokenResponseOn(String description) {
	tokenResponse(description, "on")
}
def tokenResponseOff(String description) {
	tokenResponse(description, "off")
} 
def tokenResponse(String description, String sendMsg) {
	if (logEnable) log.info 'hello received!' 
	resp=parseLanMessage(description).payload
	if (logEnable) log.info resp
	
	rdeviceID = resp.substring(16, 24)
	state.deviceID = rdeviceID
	if (logEnable) log.info "DeviceID: " + resp.substring(16,24)
	
	rstamp = hubitat.helper.HexUtils.hexStringToInt(resp.substring(24,32))
	state.stamp=rstamp
	if (logEnable) log.info "Stamp:" +rstamp
	
	rtoken =settings.token
	if (rtoken == null || rtoken =="") {
		rtoken=resp.substring(32,64)
		state.token=rtoken
		if (logEnable) log.info "Token: " + resp.substring(32,64)
	}
	
	switch (sendMsg) {
		case "status":
		sendMsgStatus(rdeviceID, rtoken, rstamp)
		break
		case "on":
		sendMsgOn(rdeviceID, rtoken, rstamp)
		break
		case "off":
		sendMsgOff(rdeviceID, rtoken, rstamp)
		break
	}
} 
def msgResponse(String description) {
	if (logEnable) log.info 'message received!!!'
	resp=parseLanMessage(description).payload
	if (logEnable) log.info resp
	decrypted = aesDecrypt(resp.substring(64,resp.length()))
	if (logEnable) log.info decrypted
	json = new groovy.json.JsonSlurper().parseText(decrypted)
	if (json.error!=null) {
	log.error 'Error returned:' +json.error.message
		return
	} 
	switch (json.id) {
		case 1: //status
			sendEvent(name: "switch", value: json.result[0], isStateChange: true)
			sendEvent(name: "temperature", value: json.result[1], isStateChange: true)
			break
		case 2: //on
			if (json.result[0]=='ok') {
				sendEvent(name: "switch", value: "on", isStateChange: true)
			} else {
				log.error 'Unknown response received:' +decrypted
			} 
		break
		case 3: //off
			if (json.result[0]=='ok') {
				sendEvent(name: "switch", value: "off", isStateChange: true)
			} else {
				log.error 'Unknown response received:' +decrypted
			} 
		break
		default:
			log.error 'Unknown response received' +json.id
		break
	} 
} 
def sendMsg(msg, rdeviceID, rtoken, rstamp) {
	if (logEnable) log.info 'sendMsg'
	msgstr=aesEncrypt(msg)
	if (logEnable) log.info msgstr
	rstamp = rstamp+1
	state.stamp = rstamp
	stampstr = hubitat.helper.HexUtils.integerToHexString(rstamp,4)
	
	checksum=rtoken
	byte[] rawBytes = [0x21, 0x31, 0x00, 0x00, 
					   0x00, 0x00, 0x00, 0x00] 
	String stringBytes = hubitat.helper.HexUtils.byteArrayToHexString(rawBytes)
	stringBytes = stringBytes + rdeviceID + stampstr + checksum + msgstr
	
	length=stringBytes.length()
	stringBytes=stringBytes.substring(0,4) + hubitat.helper.HexUtils.integerToHexString((length/2).toInteger(),2) + stringBytes.substring(8,length)
	checksum = md5(hubitat.helper.HexUtils.hexStringToByteArray(stringBytes))
	
	stringBytes=stringBytes.substring(0,32)+checksum+stringBytes.substring(64,length)
	if (logEnable) log.info stringBytes
	
	def myHubAction = new hubitat.device.HubAction(stringBytes, 
                           hubitat.device.Protocol.LAN, 
                           [type: hubitat.device.HubAction.Type.LAN_TYPE_UDPCLIENT, 
                            destinationAddress: settings.ipAddress+":54321",
                            encoding: hubitat.device.HubAction.Encoding.HEX_STRING,
							callback: msgResponse
							]) 
	if (logEnable) log.info 'sending msg: ' + stringBytes
	sendHubCommand(myHubAction)
}

def connect(callbackFunc) {
	byte[] rawBytes = [0x21, 0x31, 0x00, 0x20, 
					   0xFF, 0xFF, 0xFF, 0xFF, 
					   0xFF, 0xFF, 0xFF, 0xFF, 
					   0xFF, 0xFF, 0xFF, 0xFF, 
					   
					   0xFF, 0xFF, 0xFF, 0xFF,  
					   0xFF, 0xFF, 0xFF, 0xFF, 
					   0xFF, 0xFF, 0xFF, 0xFF, 
					   0xFF, 0xFF, 0xFF, 0xFF
					  ] 
	String stringBytes = hubitat.helper.HexUtils.byteArrayToHexString(rawBytes)
	def myHubAction = new hubitat.device.HubAction(stringBytes, 
                           hubitat.device.Protocol.LAN, 
                           [type: hubitat.device.HubAction.Type.LAN_TYPE_UDPCLIENT, 
                            destinationAddress: settings.ipAddress+":54321",
                            encoding: hubitat.device.HubAction.Encoding.HEX_STRING, 
							callback: callbackFunc]) 
											   
	if (logEnable) log.info 'sending hello' 
	sendHubCommand(myHubAction)
}

def aesEncrypt(val) {
	key = getKey();
    iv = hubitat.helper.HexUtils.hexStringToByteArray(getIV(key));
    
    if (logEnable)
        log.info 'token: '+state.token + ' key: ' + key + ' iv: ' + iv

    IvParameterSpec iv1 = new IvParameterSpec(iv);
    SecretKeySpec skeySpec = new SecretKeySpec(hubitat.helper.HexUtils.hexStringToByteArray(key), "AES");

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv1);

    byte[] encrypted = cipher.doFinal((val+"\0").getBytes());
    result = hubitat.helper.HexUtils.byteArrayToHexString(encrypted).toLowerCase();
    if (logEnable)
        log.info result
    return result;
}
def aesDecrypt(val) {
	key = getKey();
    iv = hubitat.helper.HexUtils.hexStringToByteArray(getIV(key));
    
    if (logEnable)
        log.info 'token: '+state.token + ' key: ' + key + ' iv: ' + iv

    IvParameterSpec iv1 = new IvParameterSpec(iv);
    SecretKeySpec skeySpec = new SecretKeySpec(hubitat.helper.HexUtils.hexStringToByteArray(key), "AES");

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv1);
    byte[] original = cipher.doFinal(hubitat.helper.HexUtils.hexStringToByteArray(val));

    result = new String(original);
    if (logEnable)
        log.info result
    return result;
}
def getKey() {
	return md5(hubitat.helper.HexUtils.hexStringToByteArray(state.token))
}
def getIV(key) {
	return md5(hubitat.helper.HexUtils.hexStringToByteArray(key + state.token))
}
def md5(s){
	MessageDigest.getInstance("MD5").digest(s).encodeHex().toString()
}