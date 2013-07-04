package com.streambox.wms.auth.module;

import com.amazon.thirdparty.Base64;
import com.wowza.wms.application.*;
import com.wowza.wms.amf.*;
import com.wowza.wms.client.*;
import com.wowza.wms.module.*;
import com.wowza.wms.request.*;
import com.wowza.wms.stream.*;
import com.wowza.wms.rtp.model.*;
import com.wowza.wms.httpstreamer.model.*;
import com.wowza.wms.httpstreamer.cupertinostreaming.httpstreamer.*;
import com.wowza.wms.httpstreamer.smoothstreaming.httpstreamer.*;
import com.wowza.util.URLUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ObjectUtils.Null;

public class ModuleAuth extends ModuleBase {
	
	public void onConnect(IClient client, RequestFunction function,
			AMFDataList params) {
		if (!this.validateAuth(client)){
			getLogger().info("ModuleAuth: Invalid client (" + client.getIp() + ")");
			client.rejectConnection();
		}
	}
	
	private boolean validateAuth(IClient client){
		String secret_key = client.getAppInstance().getProperties().getPropertyStr("StreamAuthKey","");
		Map<String, List<String>> queryParams = URLUtils.parseQueryStr(client.getQueryStr(), true);
		String wms_auth = getMapValue(queryParams, "wmsAuth");
		if (wms_auth.length() > 0){
			String sign = new String(Base64.decode(wms_auth));
			long current_time = System.currentTimeMillis()/1000;
			queryParams = URLUtils.parseQueryStr(sign, true);
			if (queryParams.containsKey("validminutes") && queryParams.containsKey("server_time") && queryParams.containsKey("hash_value")){
				String valid_minutes = getMapValue(queryParams, "validminutes");
				String server_time = getMapValue(queryParams, "server_time");
				String client_hash_value = getMapValue(queryParams, "hash_value");
				String server_hash_value = client.getIp()+""+secret_key+""+server_time+""+valid_minutes;
				server_hash_value = new String(DigestUtils.md5Hex(server_hash_value));
				getLogger().info("---------------------------------------------------------");
				getLogger().info("CLI HASH: "+client_hash_value);
				getLogger().info("SRV_HASH: "+server_hash_value);
				getLogger().info("Time "+current_time+" = "+server_time);
				getLogger().info("Valid minutes:"+ valid_minutes);
				getLogger().info("---------------------------------------------------------");
				if (current_time - Long.parseLong(server_time) > Integer.parseInt(valid_minutes)*60){
					getLogger().info("ModuleAuth: current_time - server_time is more than valid_minutes (" + client.getIp() + ")");
					return false;
				}
				if (client_hash_value.equals(server_hash_value)){
					getLogger().info("ModuleAuth: valid hash (" + client.getIp() + ")");
					return true;
				} else {
					getLogger().info("ModuleAuth: invalid hash (" + client.getIp() + ")");
					return false;
				}
			}
		} else {
			getLogger().info("ModuleAuth: error parse first if (" + client.getIp() + ")");
		}
		return false;
	}
	
	private String getMapValue(Map<String, List<String>> map, String searchKey){
		for (Map.Entry<String, List<String>> entry: map.entrySet()){
			String key = entry.getKey().toString();
			if (key.equals(searchKey)){
				return entry.getValue().get(0);
			}
		}
		return "";
	}
}