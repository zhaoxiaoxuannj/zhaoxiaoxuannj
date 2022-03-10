package com.ais.security.threatanalysis.entity;

import com.alibaba.fastjson.JSON;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class WapiResponse  implements Serializable {

    private static final String OK = "lang_key.csmf.global.operSuccess";
    private static final String ERROR = "lang_key.csmf.global.operateFailed";
    private static final long serialVersionUID = 8412052951904413509L;

    private boolean success = true;
    private String message;
    private Integer code = 0;  // 0--表示成功，-1--表示失败，1--表示warn(适配原来的WARN),2--表示ERR(适配原来的ERR)
    private Map<String, Object> result = null;

    public static String getOK() {
        return OK;
    }

    public static String getERROR() {
        return ERROR;
    }

    public WapiResponse success() {
        this.success = true;
        this.message = OK;
        this.code = 0;
        return this;
    }

    public WapiResponse success(String message) {
        this.success = true;
        this.message = OK;
        this.code = 0;
        this.message = message;
        return this;
    }

    public WapiResponse success(Integer code, String message) {
        this.success = true;
        this.message = OK;
        this.code = code;
        this.message = message;
        return this;
    }

    public WapiResponse success(Map<String, Object> result) {
        this.success = true;
        this.message = OK;
        this.code = 0;
        this.result = result;
        return this;
    }

    public WapiResponse failure() {
        this.success = false;
        this.message = ERROR;
        this.code = -1;
        return this;
    }

    public WapiResponse failure(String message) {
        this.success = false;
        this.message = message;
        this.code = -1;
        return this;
    }

    public void put(String name, Object value) {
        if (null == result) {
            result = new HashMap<String, Object>();
        }
        result.put(name, value);
    }

    public Object get(String name) {
        if (null == result) {
            result = new HashMap<String, Object>();
        }
        return result.get(name);
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public Map<String, Object> getResult() {
        return result;
    }

    public void setResult(Map<String, Object> result) {
        this.result = result;
    }

    @Override
    public String toString() {
        Map<String, Object> map = new HashMap<>();
        map.put("success", success);
        map.put("message", message);
        map.put("code", code);
        map.put("result", result);
        return JSON.toJSONString(map);
    }
}

