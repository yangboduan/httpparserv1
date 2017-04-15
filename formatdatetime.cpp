#include <string>
#include <ctime>
#include <stdio.h>
using namespace std;

//返回格式化的时间函数，返回的值如：2017-04-15 12:05:07
string formatdatetime(){
    time_t now = time(0);// 基于当前系统的当前日期/时间
    tm *ltm = localtime(&now);
    string syear,smonth,sday,shour,smin,ssec;
    char iyear[5],imonth[3],iday[3],ihour[3],imin[3],isec[3];

    /*把数据进行格式化，并写入数组*/
    sprintf(iyear, "%d",1900 + ltm->tm_year );
    sprintf(imonth, "%02d", 1 + ltm->tm_mon );
    sprintf(iday, "%02d", ltm->tm_mday );
    sprintf(ihour, "%02d", ltm->tm_hour );
    sprintf(imin, "%02d",  ltm->tm_min);
    sprintf(isec, "%02d",  ltm->tm_sec);

    /*字符数组转字符串*/
    syear = iyear;
    smonth = imonth;
    sday = iday;
    shour = ihour;
    smin = imin;
    ssec = isec;

    /*将日期时间的各个值构造成标准的时间格式*/        
    string datetimestr =syear + "-" + smonth + "-" + sday + " "+ shour + ":" + smin + ":" + ssec;
    return datetimestr;
}

