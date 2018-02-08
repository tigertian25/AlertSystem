package com.artwellhk.alertsystem.core;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.lang.time.DateUtils;

public class util {


	/**
	 * 计算时间差工具
	 * @param d1
	 * @param d2
	 * @return d1-d2
	 */
	public static String dateUtil(Date d1, Date d2) {
		String timeDifference = "";
		long l = d1.getTime() - d2.getTime();
		long day = l / (24 * 60 * 60 * 1000);
		long hour = (l / (60 * 60 * 1000) - day * 24);
		long min = ((l / (60 * 1000)) - day * 24 * 60 - hour * 60);
		long s = (l / 1000 - day * 24 * 60 * 60 - hour * 60 * 60 - min * 60);
		if (day > 0) {
			timeDifference += day + "天";
		}
		if (hour > 0) {
			timeDifference += hour + "小时";
		}
		if (min > 0) {
			timeDifference += min + "分";
		}
		if (s > 0) {
			timeDifference += s + "秒";
		}
		//System.out.println("" + day + "天" + hour + "小时" + min + "分" + s + "秒");
		return timeDifference;
	}
}
