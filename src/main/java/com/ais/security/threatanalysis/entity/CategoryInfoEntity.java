package com.ais.security.threatanalysis.entity;

/**
 * @author chaoyan
 * @date 2021/6/9
 */
public class CategoryInfoEntity extends CategoryGroupEntity{

    private Integer categoryCode;
    private String categoryName;


    public Integer getCategoryCode() {
        return categoryCode;
    }

    public void setCategoryCode(Integer categoryCode) {
        this.categoryCode = categoryCode;
    }

    public String getCategoryName() {
        return categoryName;
    }

    public void setCategoryName(String categoryName) {
        this.categoryName = categoryName;
    }


}
