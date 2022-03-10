package com.ais.security.threatanalysis.util;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * @author chaoyan
 * @date 2020/11/20
 */
public class TimeUtils {

    private static final SimpleDateFormat sdfYYYYMMDDHHmmss = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final SimpleDateFormat sdfYYYYMMDD = new SimpleDateFormat("yyyy-MM-dd");


    public static final DateTimeFormatter DTF_YYYYMMDD = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    public static final DateTimeFormatter DTF_YYYYMMDDHHmm = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
    public static final DateTimeFormatter DTF_YYYYMMDDHHmmss = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static final ZoneId systemZoneId = ZoneId.systemDefault();


    public static SimpleDateFormat getSdfYYYYMMDDHHmmss() {
        return (SimpleDateFormat) sdfYYYYMMDDHHmmss.clone();
    }

    public static SimpleDateFormat getSdfYYYYMMDD() {
        return (SimpleDateFormat) sdfYYYYMMDD.clone();
    }

    public static final long MILLISECOND_FORONEDAY = 1000 * 24 * 60 * 60;// 一天的毫秒数
    public static final long MILLISECOND_FORONEHOUR = 1000 * 60 * 60;// 一小时的毫秒数
    public static final long MILLISECOND_FORMINUTE = 1000 * 60;// 一分钟的毫秒数
    public static final long MILLSECOND_FORONESECOND = 1000;// 一秒钟的毫秒数
    /**
     * 获取今天的日期
     *
     * @return yyyy-MM-dd
     */
    public static String getTodayDate() {
        Calendar calendar = Calendar.getInstance();
        return getSdfYYYYMMDD().format(calendar.getTime());
    }

    public static String getYesterdayDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, -1);
        return getSdfYYYYMMDD().format(calendar.getTime());
    }

    public static List<String> getBetweenDates(Date start, Date end) {
        List<String> result = new ArrayList<>();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(start);
        while (calendar.getTime().before(end)) {
            result.add(sdf.format(calendar.getTime()));
            calendar.add(Calendar.DAY_OF_MONTH, 1);
        }
        result.add(sdf.format(end));
        return result;
    }


    public static LocalDateTime timestamp2LocalDateTime(long timestamp) {
        return Instant.ofEpochMilli(timestamp).atZone(systemZoneId).toLocalDateTime();
    }

    public static LocalDateTime date2LocalDateTime(Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), systemZoneId);
    }


    public static Date localDateTime2Date(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(systemZoneId).toInstant());
    }

    public static LocalDateTime max(LocalDateTime o1, LocalDateTime o2) {
        return o1.compareTo(o2) > 0 ? o1 : o2;
    }

    public static LocalDateTime min(LocalDateTime o1, LocalDateTime o2) {
        return o1.compareTo(o2) < 0 ? o1 : o2;
    }

    public static LocalDateTime getStartOfDay(LocalDateTime localDateTime){
        return localDateTime.withHour(0).withMinute(0).withSecond(0).withNano(0);
    }
    public static LocalDateTime getEndOfDay(LocalDateTime localDateTime){
        return localDateTime.withHour(23).withMinute(59).withSecond(59);
    }

    /**
     * 格式化时间差 输出x年x月x天
     *
     * @param startTime
     * @param endTime
     * @return
     */
    public static String formatDuration(String startTime, String endTime) {
        LocalDate start = LocalDateTime.parse(startTime, DTF_YYYYMMDDHHmmss).toLocalDate();
        LocalDate end = LocalDateTime.parse(endTime, DTF_YYYYMMDDHHmmss).toLocalDate();
        if (end.isBefore(start)) {
            return null;
        }

        end = end.plusDays(1);
        StringBuilder sb = new StringBuilder();
        Period p = Period.between(start, end);
        if (p.getYears() > 0) {
            sb.append(p.getYears()).append("年");
        }
        if (p.getMonths() > 0) {
            sb.append(p.getMonths()).append("月");
        }
        if (p.getDays() > 0) {
            sb.append(p.getDays()).append("天");
        }
        return sb.toString();
    }
    //最大时间差用天表示
    public static String formatDuration2(String endTime,String startTime) {
        long start = LocalDateTime.parse(startTime, DTF_YYYYMMDDHHmmss).toInstant(ZoneOffset.of("+8")).toEpochMilli();
        long end = LocalDateTime.parse(endTime, DTF_YYYYMMDDHHmmss).toInstant(ZoneOffset.of("+8")).toEpochMilli();
        if (end<=start) {
            return null;
        }
//    SimpleDateFormat sd = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        long diff;
        long day = 0;
        long hour = 0;
        long min = 0;
        long sec = 0;
        // 获得两个时间的毫秒时间差异
        diff = end-start;
        day = diff / MILLISECOND_FORONEDAY;// 计算差多少天
        hour = diff % MILLISECOND_FORONEDAY / MILLISECOND_FORONEHOUR + day * 24;// 计算差多少小时
        min = diff % MILLISECOND_FORONEDAY % MILLISECOND_FORONEHOUR / MILLISECOND_FORMINUTE + day * 24 * 60;// 计算差多少分钟
        sec = diff % MILLISECOND_FORONEDAY % MILLISECOND_FORONEHOUR % MILLISECOND_FORMINUTE / MILLSECOND_FORONESECOND;// 计算差多少秒
        // 输出结果
        StringBuilder sb = new StringBuilder();
        if (day > 0) {
            sb.append(day).append("天");
        }

        if (hour > 0) {
            sb.append(hour<10?("0"+hour):hour).append(":");
        }
        else {
            sb.append("00").append(":");
        }
        if (min > 0) {
            sb.append(min<10?("0"+min):min).append(":");
        }
        else {
            sb.append("00").append(":");
        }
        if (sec > 0) {
            sb.append(sec<10?("0"+sec):sec);
        }
        else {
            sb.append("00");
        }
        String result=sb.toString().endsWith(":")?sb.toString().substring(0,sb.toString().length()-1):sb.toString();
        return result;
    }
    public static boolean assertNotEqualDay(String requestTime){
        int currentday=LocalDateTime.now().getDayOfYear();
        int logcurrentday=LocalDateTime.parse(requestTime, TimeUtils.DTF_YYYYMMDDHHmmss).getDayOfYear();
        return currentday!=logcurrentday;
    }

    public static void main(String[] args) {
        TimeUtils.formatDuration2("2021-12-31 10:05:02","2021-12-30 12:08:04");
    }
}
