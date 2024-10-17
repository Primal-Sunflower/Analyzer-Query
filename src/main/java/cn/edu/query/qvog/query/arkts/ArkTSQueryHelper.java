package cn.edu.query.qvog.query.arkts;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ArkTSQueryHelper {
    public static String RESOURCE_HAS_BEEN_RELEASED = "the resource has been released:";
    public static String RESOURCE_FORGET_TO_RELEASE = "the resource is forget to release:";
    public static String OPERATiON_OPTIMIZE_BY_COMPILER = "the operation may be optimized by compiler:";

    public static String FUNCTION_OUTDATED = "%s function has been outdated, please use %s:";

    public static HashMap<String, String> outDatedFunctionMap;
    public static HashMap<String, String> printf2TypeMap;

    static {
        outDatedFunctionMap = new HashMap<>();
        outDatedFunctionMap.put("gets", "fgets");
        outDatedFunctionMap.put("gmtime", "gmtime_r");
        outDatedFunctionMap.put("memset", "memset_s");
        outDatedFunctionMap.put("bzero", "memset_s");
        outDatedFunctionMap.put("sprintf", "snprintf");
        outDatedFunctionMap.put("strcpy", "strncpy");
        outDatedFunctionMap.put("3DES", "AES");

        printf2TypeMap = new HashMap<>();
        printf2TypeMap.put("s", "char *");
        printf2TypeMap.put("d", "int");
        printf2TypeMap.put("f", "float");
        printf2TypeMap.put("lf", "double");
        printf2TypeMap.put("ld", "long long");
    }

    public static Boolean compareTypeSize(Long sourceSize, Type destType) {
        try {
            int destSize = getTypeSize(destType);
            if (destSize != -1 && sourceSize <= destSize) {
                return true;
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    public static int getTypeSize(Type type) {
        if (type instanceof IntegerType integerType) {
            return getTypeSize(integerType);
        } else if (type instanceof PointerType pointerType) {
            return getTypeSize(pointerType);
        }
        return -1;
    }

    public static int getTypeSize(IntegerType integerType) {
        String name = integerType.getName();
        try {
            return Integer.parseInt(name);
        } catch (Exception e) {
            return -1;
        }
    }

    public static int getTypeSize(PointerType pointerType) {
        String pointerName = pointerType.getName();
        try {
            return Integer.parseInt(pointerName.substring(pointerName.indexOf('[') + 1, pointerName.indexOf(']')));
        } catch (Exception e) {
            return -1;
        }
    }

    // size: source type should <= dest type
    public static Boolean compareTypeSize(Type sourceType, Type destType) {
        try {
            int sourceSize = getTypeSize(sourceType);
            int destSize = getTypeSize(destType);
            if (sourceSize != -1 && destSize != -1 && sourceSize <= destSize) {
                return true;
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    // return if it has problem
    public static Boolean checkPrintfLikeLiteralLegal(String literal, List<Expression> arguments) {
        List<String> formats = new ArrayList<>();
        Pattern pattern = Pattern.compile("%(s|d|f|lf|ld)");
        Matcher matcher = pattern.matcher(literal);
        while (matcher.find()) {
            formats.add(matcher.group());
        }

        // size check
        if (formats.size() != arguments.size()) {
            return true;
        }
        // type check
        for (int i = 0; i < arguments.size(); i++) {
            Expression arg = arguments.get(i);
            String expectedType = printf2TypeMap.get(formats.get(i).substring(1));
            if (arg instanceof Reference variable) {
                String type = variable.getType().getName();
                if (!type.equals(expectedType)) {
                    return true;
                }
            } else if (arg instanceof Literal argLiteral) {
                String type = argLiteral.getType().getName();
                if (!type.equals(expectedType)) {
                    return true;
                }
            }
        }
        return false;
    }
}
