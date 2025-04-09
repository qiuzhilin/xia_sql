package org.burp;



import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import java.util.List;

public class CommonUtil {
    /**
     * 递归提取JSON对象中的所有路径
     * @param obj 要提取路径的JSON对象或数组
     * @param currentPath 当前处理的路径
     * @param paths 存储提取出的路径列表
     */
    public static void extractPaths(Object obj, String currentPath, List<String> paths) {
        // 处理JSON对象的情况
        if (obj instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) obj;
            // 遍历JSON对象中的所有key
            for (String key : jsonObject.keySet()) {
                Object value = jsonObject.get(key);
                // 构建新路径：如果当前路径为空则直接使用key，否则用点号连接
                String newPath = currentPath.isEmpty() ? key : currentPath + "." + key;
                // 移除中间路径，只保留到叶子节点的完整路径
                paths.remove(currentPath);
                paths.add(newPath);
                // 递归处理嵌套结构
                extractPaths(value, newPath, paths);
            }
        } else if (obj instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) obj;
            // 只处理非空数组(使用第一个元素作为模板)
            if (!jsonArray.isEmpty()) {
                Object firstElement = jsonArray.get(0);
                // 在路径后添加数组索引标记
                String newPath = currentPath + "[0]";
                // 移除中间路径
                paths.remove(currentPath);
                paths.add(newPath);
                // 递归处理数组元素
                extractPaths(firstElement, newPath, paths);
            }
        }
    }

    /**
     * 根据指定路径更新JSON结构中的值
     * 处理三种路径格式:
     * 1. 简单路径("key")
     * 2. 点号路径("parent.child")
     * 3. 数组路径("array[0].property" 或 "array[0][1]")
     */
    public static void updateValueByPath(JSONObject jsonObject, String path, Object newValue) {
        // 特殊情况：直接数组访问(如"skills[0]")
        if (path.contains("[") && !path.contains(".")) {
            String arrayKey = path.substring(0, path.indexOf("["));
            int index = Integer.parseInt(path.substring(path.indexOf("[") + 1, path.indexOf("]")));
            ((JSONArray) jsonObject.get(arrayKey)).set(index, newValue);
            return;
        }

        // 将路径拆分为组件以便分层导航
        String[] keys = path.split("\\.");
        Object currentObj = jsonObject;

        // 遍历路径组件(最后一个除外)
        for (int i = 0; i < keys.length - 1; i++) {
            String key = keys[i];
            // 处理路径中的数组标记(如"items[0]")
            if (key.contains("[")) {
                String arrayKey = key.substring(0, key.indexOf("["));
                int index = Integer.parseInt(key.substring(key.indexOf("[") + 1, key.indexOf("]")));

                // 从当前对象获取数组引用
                if (currentObj instanceof JSONObject) {
                    currentObj = ((JSONObject) currentObj).get(arrayKey);
                }

                // 获取特定数组元素
                if (currentObj instanceof JSONArray) {
                    currentObj = ((JSONArray) currentObj).get(index);
                }
            } else {
                // 简单对象属性访问
                if (currentObj instanceof JSONObject) {
                    currentObj = ((JSONObject) currentObj).get(key);
                }
            }
        }

        // 更新最后路径组件处的值
        String lastKey = keys[keys.length - 1];
        // 情况1: 最后组件是数组索引(如"techStack[0]")
        if (lastKey.contains("[")) {
            String arrayKey = lastKey.substring(0, lastKey.indexOf("["));
            int index = Integer.parseInt(lastKey.substring(lastKey.indexOf("[") + 1, lastKey.indexOf("]")));
            ((JSONArray) ((JSONObject) currentObj).get(arrayKey)).set(index, newValue);
        }
        // 情况2: 最后组件是对象属性
        else if (currentObj instanceof JSONObject) {
            ((JSONObject) currentObj).put(lastKey, newValue);
        }
        // 情况3: 最后组件是数组索引(数字字符串)
        else if (currentObj instanceof JSONArray) {
            ((JSONArray) currentObj).set(Integer.parseInt(lastKey), newValue);
        }
    }

    /**
     * 根据路径获取JSON中的值
     * @param jsonObject JSON对象
     * @param path 要获取值的路径
     * @return 路径对应的值，如果路径不存在返回null
     */
    public static Object getValueByPath(JSONObject jsonObject, String path) {
        try {
            // 特殊情况：直接数组访问(如"skills[0]")
            if (path.contains("[") && !path.contains(".")) {
                String arrayKey = path.substring(0, path.indexOf("["));
                int index = Integer.parseInt(path.substring(path.indexOf("[") + 1, path.indexOf("]")));
                return ((JSONArray) jsonObject.get(arrayKey)).get(index);
            }

            // 将路径拆分为组件以便分层导航
            String[] keys = path.split("\\.");
            Object currentObj = jsonObject;

            // 遍历路径组件
            for (String key : keys) {
                if (key.contains("[")) {
                    // 处理数组标记(如"items[0]")
                    String arrayKey = key.substring(0, key.indexOf("["));
                    int index = Integer.parseInt(key.substring(key.indexOf("[") + 1, key.indexOf("]")));

                    // 从当前对象获取数组引用
                    if (currentObj instanceof JSONObject) {
                        currentObj = ((JSONObject) currentObj).get(arrayKey);
                    }

                    // 获取特定数组元素
                    if (currentObj instanceof JSONArray) {
                        currentObj = ((JSONArray) currentObj).get(index);
                    }
                } else {
                    // 简单对象属性访问
                    if (currentObj instanceof JSONObject) {
                        currentObj = ((JSONObject) currentObj).get(key);
                    }
                }

                if (currentObj == null) {
                    return null;
                }
            }

            return currentObj;
        } catch (Exception e) {
            return null; // 路径无效时返回null
        }
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
}
