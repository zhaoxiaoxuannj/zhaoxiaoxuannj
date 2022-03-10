package com.ais.security.threatanalysis.mapper;

import com.ais.security.threatanalysis.entity.GlobalAddressLibrary;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.util.List;

@Mapper
public interface IpLocationInfoMapper {

    @Select("select * from IP_LOCATION_INFO")
    List<GlobalAddressLibrary> selectAllInfo();


    @Select("select * from IP_LOCATION_INFO order by startIpLong asc")
    List<GlobalAddressLibrary> getAllOrderByStartIpAsc();

    @Update("<script>" +
            "insert into IP_LOCATION_INFO (start_ip,end_ip,location,startIpLong,endIpLong)\n" +
            "        values\n" +
            "            <foreach collection=\"list\" index=\"index\" separator=\",\" item=\"item\">\n" +
            "                (#{item.startIp},#{item.endIp},#{item.location},#{item.startIpLong},#{item.endIpLong})\n" +
            "            </foreach>\n" +
            "        ON DUPLICATE KEY UPDATE\n" +
            "        startIpLong = values (startIpLong),\n" +
            "        endIpLong = values (endIpLong)" +
            "</script>")
    int batchUpdate(@Param("list") List<GlobalAddressLibrary> list);
}
