package com.ais.security.threatanalysis.entity;

import java.io.Serializable;
import java.math.BigInteger;

public class GlobalAddressLibrary implements Comparable<GlobalAddressLibrary>, Serializable {
    private static final long serialVersionUID = 1;
    private int id;
    private String startIp;
    private String endIp;
    private String location;
    private BigInteger startIpLong;
    private BigInteger endIpLong;

    public GlobalAddressLibrary() {
    }

    public GlobalAddressLibrary(BigInteger startIpLong) {
        this.startIpLong = startIpLong;
        this.endIpLong = startIpLong;
    }

    @Override
    public int compareTo(GlobalAddressLibrary ip) {
        BigInteger start = this.startIpLong.subtract(ip.startIpLong);
        BigInteger end = this.endIpLong.subtract(ip.endIpLong);
        BigInteger zero = BigInteger.valueOf(0);
        if (start.compareTo(zero) > 0) {
            return 1;
        } else if (start.compareTo(zero) <= 0 && end.compareTo(zero) >= 0) {
            return 0;
        } else {
            return -1;
        }
    }


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }


    public String getStartIp() {
        return startIp;
    }

    public void setStartIp(String startIp) {
        this.startIp = startIp;
    }

    public String getEndIp() {
        return endIp;
    }

    public void setEndIp(String endIp) {
        this.endIp = endIp;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public BigInteger getStartIpLong() {
        return startIpLong;
    }

    public void setStartIpLong(BigInteger startIpLong) {
        this.startIpLong = startIpLong;
    }

    public BigInteger getEndIpLong() {
        return endIpLong;
    }

    public void setEndIpLong(BigInteger endIpLong) {
        this.endIpLong = endIpLong;
    }

    @Override
    public String toString() {
        return "GlobalAddressLibrary{" +
                "id=" + id +
                ", startIp='" + startIp + '\'' +
                ", endIp='" + endIp + '\'' +
                ", location='" + location + '\'' +
                ", startIpLong=" + startIpLong +
                ", endIpLong=" + endIpLong +
                '}';
    }


}
