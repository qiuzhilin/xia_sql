package org.burp;


import com.alibaba.fastjson.JSONPath;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CommonUtil {
    public static void main(String[] args) {
        String jsonstr="{\n" +
                "  \"string_example\": \"Hello, world!\",\n" +
                "  \"number_integer\": 42,\n" +
                "  \"number_float\": 3.14159,\n" +
                "  \"boolean_true\": true,\n" +
                "  \"boolean_false\": false,\n" +
                "  \"null_value\": null,\n" +
                "  \"object_example\": {\n" +
                "    \"nested_string\": \"Nested value\",\n" +
                "    \"nested_number\": 100,\n" +
                "    \"nested_array\": [1, 2, 3],\n" +
                "    \"deep_object\": {\n" +
                "      \"level_2_key\": \"Level 2 value\",\n" +
                "      \"level_2_array\": [\n" +
                "        {\n" +
                "          \"id\": 1,\n" +
                "          \"name\": \"Alice\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"id\": 2,\n" +
                "          \"name\": \"Bob\"\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  },\n" +
                "  \"array_example\": [\n" +
                "    \"item1\",\n" +
                "    123,\n" +
                "    false,\n" +
                "    null,\n" +
                "    {\n" +
                "      \"inner_object_key\": \"inner value\",\n" +
                "      \"inner_array\": [10, 20, 30],\n" +
                "      \"info\": {\n" +
                "        \"author\": \"John Doe\",\n" +
                "        \"version\": 1.0,\n" +
                "        \"active\": true,\n" +
                "        \"tags\": [\"example\", \"test\", \"json\"]\n" +
                "      }\n" +
                "    },\n" +
                "    [\n" +
                "      \"nested array item1\",\n" +
                "      {\n" +
                "        \"deep_nested\": \"yes\"\n" +
                "      }\n" +
                "    ]\n" +
                "  ]\n" +
                "}\n";
        JSONObject obj = JSON.parseObject(jsonstr);
        List<String>  path=new ArrayList<>();
        extractPaths(obj," ",path);
        for(String s:path){
            System.out.println(s);
            String tres1= String.valueOf(JSONPath.read(jsonstr,"$"+s));
            System.out.println(tres1);
            JSONPath.set(obj,"$"+s,tres1+"888");

        }
        //JSONPath.set(obj,"$.array_example[4].inner_object_key","no");
        System.out.println(obj);
    }

    /**
     * 提取json 路径
     * @param obj
     * @param currentPath
     * @param paths
     */
    public static void extractPaths(Object obj, String currentPath, List<String> paths) {
        if (obj instanceof JSONObject) {
            // 遍历 JSONObject 对象
            JSONObject jsonObject = (JSONObject) obj;
            Iterator<Map.Entry<String, Object>> iterator = jsonObject.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, Object> entry = iterator.next();
                extractPaths(entry.getValue(), currentPath + "." + entry.getKey(), paths);
            }
        } else if (obj instanceof JSONArray) {
            // 遍历 JSONArray 数组
            JSONArray jsonArray = (JSONArray) obj;
            //数组内是同一类型，只获取第一个元素payloay
            if(isSameTypeArray(jsonArray)) {
                // 获取第一个元素的路径
                Object firstElement = jsonArray.get(0);
                // 如果第一个元素是 JSONObject 或 JSONArray，递归处理
                if (firstElement instanceof JSONObject) {
                    extractPaths(firstElement, currentPath + "[0]", paths);
                } else if (firstElement instanceof JSONArray) {
                    extractPaths(firstElement, currentPath + "[0]", paths);
                }else{
                    paths.add(currentPath+"[0]");
                }
            }else {
                for (int i = 0; i < jsonArray.size(); i++) {
                    extractPaths(jsonArray.get(i), currentPath + "[" + i + "]", paths);
                }
            }
        } else {
            // 如果是叶子节点，添加路径
            paths.add(currentPath);
        }
    }
    // 判断数组内的所有元素是否是同一类型
    public static boolean isSameTypeArray(JSONArray jsonArray) {
        if (jsonArray.isEmpty()) return true;  // 空数组视为相同类型

        Object firstElement = jsonArray.get(0);
        for (int i = 1; i < jsonArray.size(); i++) {
            Object currentElement = jsonArray.get(i);
            if (!firstElement.getClass().equals(currentElement.getClass())) {
                return false; // 一旦发现类型不同，返回 false
            }
        }
        return true;
    }

    /**
     * 合并json
     * @param target
     * @param source
     * @return
     */
    public static JSONObject merge(JSONObject target, JSONObject source) {
        for (String key : source.keySet()) {
            target.put(key, source.get(key));
        }
        return target;
    }

    /**
     * 从字符串中分析出最大的参数，
     * @param input
     * @return
     */
    public static int getMaxNumberFromString(String input) {
        int max = 0;

        if (input == null || input.isEmpty()) {
            return -1; // 或者抛异常，看你业务需求
        }

        // 正则匹配所有正整数
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\d+");
        java.util.regex.Matcher matcher = pattern.matcher(input);

        while (matcher.find()) {
            int number = Integer.parseInt(matcher.group());
            if (number > max) {
                max = number;
            }
        }

        // 没找到数字
        if (max == 0) {
            return -1; // 或抛异常
        }

        return max;
    }
}
