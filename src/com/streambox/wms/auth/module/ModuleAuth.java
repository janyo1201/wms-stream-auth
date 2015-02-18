package com.streambox.wms.auth.module;

import com.amazon.thirdparty.Base64;
import com.wowza.util.URLUtils;
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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ObjectUtils.Null;


public class ModuleAuth extends ModuleBase {

	private class Client
	{
		public String ip = "";
		public String query = "";
		public Client(IClient client)
		{
			ip = client.getIp();
			query = client.getQueryStr();
		}
		
		public Client(IHTTPStreamerSession client)
		{
			ip = client.getIpAddress();
			query = client.getQueryStr();
		}
		
		public Client(RTPSession client)
		{
			ip = client.getIp();
			query = client.getQueryStr();
		}
	}
	
	protected String secret_key;
	protected Client client;
	
    public void onAppStart(IApplicationInstance ai)
    {
    	secret_key = ai.getProperties().getPropertyStr("StreamAuthKey", "");
    }
	
	public void onConnect(IClient client, RequestFunction function,
			AMFDataList params) {
		Client myClient = new Client(client);
		getLogger().info("onConnect ============================================");
		if (!this.validateAuth(myClient)){
			
			client.rejectConnection();
		}
	}

	public void onHTTPSessionCreate(IHTTPStreamerSession httpSession) {
		Client myClient = new Client(httpSession);
		getLogger().info("onHTTPSessionCreate ============================================");
		if (!this.validateAuth(myClient)) {
			httpSession.rejectSession();
			httpSession.shutdown();
		}
	}

	public void onRTPSessionCreate(RTPSession rtpSession) {
		getLogger().info("onRTPSessionCreate: " + rtpSession.getSessionId());
		Client myClient = new Client(rtpSession);
		if (!this.validateAuth(myClient)) {
			rtpSession.rejectSession();
		}
	}

	
	private boolean validateAuth(Client client){
		if (client == null || client.query == null || client.query.length() == 0) {
			return false;
		}
		Map<String, List<String>> queryParams = URLUtils.parseQueryStr(client.query, true);
		String wms_auth = getMapValue(queryParams, "wmsAuth");
		String valid_minutes = "";
		String server_time = "";
		String client_hash_value = "";
		String server_hash_value = "";
		if (wms_auth.length() > 0){
			String sign = new String(Base64.decode(wms_auth));
			long current_time = System.currentTimeMillis()/1000;
			queryParams = URLUtils.parseQueryStr(sign, true);
			if (queryParams.containsKey("validminutes") && queryParams.containsKey("server_time") && queryParams.containsKey("hash_value")){
				try {
					valid_minutes = Integer.toString(Integer.parseInt(getMapValue(queryParams, "validminutes")));
					server_time = Integer.toString(Integer.parseInt(getMapValue(queryParams, "server_time")));
					client_hash_value = getMapValue(queryParams, "hash_value");
					server_hash_value = client.ip+""+secret_key+""+server_time+""+valid_minutes;
				} catch (NumberFormatException e) {
					return false;
				}
				server_hash_value = new String(DigestUtils.md5Hex(server_hash_value));
				getLogger().info("---------------------------------------------------------");
				getLogger().info("CLI HASH: "+client_hash_value);
				getLogger().info("SRV_HASH: "+server_hash_value);
				getLogger().info("Time "+current_time+" = "+server_time);
				getLogger().info("Valid minutes:"+ valid_minutes);
				getLogger().info("---------------------------------------------------------");
				if (current_time - Long.parseLong(server_time) > Integer.parseInt(valid_minutes)*60){
					getLogger().info("ModuleAuth: current_time - server_time is more than valid_minutes (" + client.ip + ")");
					return false;
				}
				if (client_hash_value.equals(server_hash_value)){
					getLogger().info("ModuleAuth: valid hash (" + client.ip + ")");
					return true;
				} else {
					getLogger().info("ModuleAuth: invalid hash (" + client.ip + ")");
					return false;
				}
			}
		} else {
			getLogger().info("ModuleAuth: error parse first if (" + client.ip + ")");
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