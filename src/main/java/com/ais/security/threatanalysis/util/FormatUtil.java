package com.ais.security.threatanalysis.util;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author chaoyan
 * @date 2020/11/19
 */
public class FormatUtil {
    private static final Logger log = LogManager.getLogger(FormatUtil.class);

    public static List<Map<String, String>> turnValueToString(List<Map<String, Object>> records) {
        List<Map<String, String>> newRecords = new ArrayList<>();

        for (Map<String, Object> record : records) {
            newRecords.add(turnValueToString(record));
        }

        return newRecords;
    }

    public static Map<String, String> turnValueToString(Map<String, Object> record) {
        Map<String, String> newRecord = new HashMap<>();

        for (String key : record.keySet()) {
            newRecord.put(key, String.valueOf(record.get(key)));
        }

        return newRecord;
    }

    public static List<Map> turnEntityToMap(List<Object> entities) {
        List<Map> list = new ArrayList<>();
        for (Object entity : entities) {
            list.add(JSON.parseObject(JSON.toJSONString(entity), Map.class));
        }
        return list;
    }

    public static List<Map<String, Object>> turnEntity2Map(List<Object> entities) {
        List<Map<String, Object>> list = new ArrayList<>();
        if(entities == null || entities.size() == 0){
            return list;
        }
        Map<String, Object> map;
        for (Object entity : entities) {
            map = new HashMap<>();
            //拿到实体的class
            Class clazz = entity.getClass();
            //获得某个类的所有声明的字段，即包括public、private和proteced，但是不包括父类的申明字段
            Field[] fields = clazz.getDeclaredFields();
            try {
                for (Field field : fields) {
                    field.setAccessible(true);
                    //直接put
                    map.put(field.getName(), field.get(entity));
                }
                list.add(map);
            } catch (Exception e) {
                log.error(e);
            }
        }

        return list;
    }


    public static <T> T turnMapToEntity(Map<String, Object> map, Class<T> clazz) {
        try {
            T object = clazz.getDeclaredConstructor().newInstance();
            Field[] fields = clazz.getDeclaredFields();
            if (fields.length > 0){
                for (Field field : fields){
                    doTurnMapToEntity(object,field,map);
                }
            }
            return object;
        } catch (Exception e) {
            log.error("map转实体类[{}]失败，原因：{}", clazz, e.getMessage());
            return null;
        }
    }

    private static void doTurnMapToEntity(Object object,Field field,Map<String, Object> map) throws IllegalAccessException {
        //当属性的修饰符为private,需要setAccessible(true);
        if (!field.isAccessible()){
            field.setAccessible(true);
        }
        JsonProperty annotation = field.getAnnotation(JsonProperty.class);
        String fieldName;
        if (null == annotation){
            fieldName = field.getName();
        } else {
            fieldName = annotation.value();
        }
        Object fieldValue = map.get(fieldName);
        if (fieldValue != null) {
            if (field.getType() == Integer.class) {
                field.set(object, Integer.parseInt(fieldValue.toString()));
            } else if (field.getType() == String.class) {
                field.set(object, fieldValue.toString());
            } else {
                field.set(object, fieldValue);
            }
        }
    }

    public static <T> T turnRequestToEntity(HttpServletRequest request, Class<T> clazz) {
        try {
            T object = clazz.getDeclaredConstructor().newInstance();
            Field[] fields = clazz.getDeclaredFields();
            if (fields.length > 0){
                for (Field field : fields){
                    doTurnRequestToEntity(object,field,request);
                }
            }
            return object;
        } catch (Exception e) {
            log.error("request转实体类[{}]失败，原因：{}", clazz, e.getMessage());
            return null;
        }
    }
    private static void doTurnRequestToEntity(Object object,Field field,HttpServletRequest request) throws IllegalAccessException {
        //当属性的修饰符为private,需要setAccessible(true);
        if (!field.isAccessible()){
            field.setAccessible(true);
        }
        JsonProperty annotation = field.getAnnotation(JsonProperty.class);
        String fieldName;
        if (null == annotation){
            fieldName = field.getName();
        } else {
            fieldName = annotation.value();
        }
        String fieldValue = request.getParameter(fieldName);
        if (fieldValue != null && fieldValue.length() > 0) {
            if (field.getType() == Integer.class) {
                field.set(object, Integer.parseInt(fieldValue));
            } else if (field.getType() == String.class) {
                field.set(object, fieldValue);
            }else{
                //do nothing
            }
        }
    }
}
