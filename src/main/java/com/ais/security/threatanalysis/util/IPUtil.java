package com.ais.security.threatanalysis.util;


import com.ais.security.threatanalysis.entity.GlobalAddressLibrary;
import org.apache.http.conn.util.InetAddressUtils;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;

public class IPUtil {

	public static String getIpAddress(String ip) throws UnknownHostException {
		if (InetAddressUtils.isIPv4Address(ip)) {
			return ip;
		} else if (InetAddressUtils.isIPv6Address(ip)) {
			InetAddress a = InetAddress.getByName(ip);
			return a.getHostAddress();
		} else {
			return "";
		}
	}

	public static GlobalAddressLibrary IpBinarySearch(String ip, List<GlobalAddressLibrary> list) {
		GlobalAddressLibrary globalAddressLibrary = null;
		BigInteger ipLong = IpConvert.StringToBigInt(ip);
		int index = Collections.binarySearch(list, new GlobalAddressLibrary(ipLong));
		if (index >= 0) {
			if (list.get(index).getEndIpLong().compareTo(ipLong) >= 0) {
				GlobalAddressLibrary temp = list.get(index);
				globalAddressLibrary = new GlobalAddressLibrary();
				globalAddressLibrary.setStartIp(ip);
				globalAddressLibrary.setLocation(temp.getLocation());
			}
		}
		return globalAddressLibrary;
	}

}
