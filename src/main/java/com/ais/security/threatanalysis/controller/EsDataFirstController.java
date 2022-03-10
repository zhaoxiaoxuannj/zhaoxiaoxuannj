package com.ais.security.threatanalysis.controller;

import com.ais.security.threatanalysis.entity.DdiThreatReportParams;
import com.ais.security.threatanalysis.entity.WapiResponse;
import com.ais.security.threatanalysis.service.impl.DdiThreatReportForSiChuanServiceImpl;
import com.ais.security.threatanalysis.util.FormatUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @Description TODO
 * @Date 2021/7/28 17:02
 * @Author yc
 * @Version 1.0
 **/
@RestController
public class EsDataFirstController {
private final Logger log = LoggerFactory.getLogger(EsDataFirstController.class);




    @Autowired
    private DdiThreatReportForSiChuanServiceImpl ddiThreatReportService;



//    @ApiOperation(value = "TOP10失陷资产")
//    @ApiImplicitParams({
//            @ApiImplicitParam(name = "statPeriod", value = "统计周期，0：今天；1：昨天；2：近7天；3：近30天；4：近90天", required = true, paramType = "query", dataTypeClass = Integer.class),
//            @ApiImplicitParam(name = "tenantId", value = "租户Id", required = true, paramType = "query", dataTypeClass = Integer.class)
//    })
    @GetMapping(value = "/ddiTopLostAsset")
    public WapiResponse getDdiTopLostAsset(HttpServletRequest request) {
        log.info("=====查询TOP10失陷资产分布，参数：{}=====", request.getParameterMap());
        DdiThreatReportParams params = FormatUtil.turnRequestToEntity(request, DdiThreatReportParams.class);

        if (params == null || params.getTenantId() == null || params.getStatPeriod() == null) {
            log.error("查询TOP10失陷资产分布，参数有误");
            return new WapiResponse().failure();
        }

        return ddiThreatReportService.getDdiTopLostAsset(params);
    }







}
