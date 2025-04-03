package org.burp;


import com.alibaba.fastjson2.JSONArray;
import jdk.nashorn.internal.parser.JSONParser;

public class App
{
    public static void main( String[] args )
    {
        String[] mork={"sort=createtime","test=createtime"};
        for(String curstomparam:mork){
            System.out.println(curstomparam);
        }
        // JSON 数组字符串
        String jsonString = "[\"'\", \"''\"]";
        // 将 JSON 字符串解析成 JSONArray
        JSONArray jsonArray = JSONArray.parseArray(jsonString);

        // 输出结果
        System.out.println(jsonArray.toString());  // ["'", "''"]

        // 访问单个元素
        System.out.println(jsonArray.getString(0));  // '
        System.out.println(jsonArray.getString(1));  // ''
    }
}
