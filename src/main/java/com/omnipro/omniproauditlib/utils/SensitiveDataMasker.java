package com.omnipro.omniproauditlib.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;
import java.util.*;

/**
 * Utility class for masking sensitive data in audit logs.
 * Automatically detects and masks fields containing sensitive information
 * based on field name patterns.
 */
@Slf4j
public class SensitiveDataMasker {

    private static final String MASK = "****";

    private static final Set<String> SENSITIVE_PATTERNS = Set.of(
            "password",
            "passwd",
            "secret",
            "key",
            "token",
            "auth",
            "credential",
            "pin",
            "cvv",
            "cvc",
            "ssn",
            "apikey",
            "api_key",
            "accesstoken",
            "access_token",
            "refreshtoken",
            "refresh_token",
            "bearer",
            "authorization",
            "private",
            "otp",
            "mpin",
            "transactionpin",
            "transaction_pin",
            "cardnumber",
            "card_number",
            "accountnumber",
            "account_number",
            "routingnumber",
            "routing_number",
            "bvn",
            "nin",
            "encrypteddata",
            "encrypted_data",
            "cipher",
            "hash"
    );

    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Checks if a field name matches any sensitive pattern.
     */
    public static boolean isSensitive(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        String normalized = fieldName.toLowerCase().replaceAll("[_\\-\\s]", "");
        return SENSITIVE_PATTERNS.stream()
                .anyMatch(pattern -> normalized.contains(pattern.replace("_", "")));
    }

    /**
     * Masks a value if the field name is sensitive.
     */
    public static Object maskIfSensitive(String fieldName, Object value) {
        if (value == null) {
            return null;
        }
        if (isSensitive(fieldName)) {
            return MASK;
        }
        return value;
    }

    /**
     * Masks sensitive fields in a Map.
     */
    public static Map<String, Object> maskMap(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        Map<String, Object> masked = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (isSensitive(key)) {
                masked.put(key, MASK);
            } else if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                masked.put(key, maskMap(nestedMap));
            } else if (value instanceof List) {
                masked.put(key, maskList((List<?>) value));
            } else if (value != null && isComplexObject(value)) {
                masked.put(key, maskObject(value));
            } else {
                masked.put(key, value);
            }
        }
        return masked;
    }

    /**
     * Masks sensitive fields in a List.
     */
    public static List<Object> maskList(List<?> data) {
        if (data == null) {
            return null;
        }
        List<Object> masked = new ArrayList<>();
        for (Object item : data) {
            if (item instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> mapItem = (Map<String, Object>) item;
                masked.add(maskMap(mapItem));
            } else if (item instanceof List) {
                masked.add(maskList((List<?>) item));
            } else if (item != null && isComplexObject(item)) {
                masked.add(maskObject(item));
            } else {
                masked.add(item);
            }
        }
        return masked;
    }

    /**
     * Masks sensitive fields in an arbitrary object using reflection.
     */
    public static Object maskObject(Object obj) {
        if (obj == null) {
            return null;
        }

        // Handle primitives and common types
        if (obj instanceof String || obj instanceof Number || obj instanceof Boolean) {
            return obj;
        }

        // Handle Maps directly
        if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> mapObj = (Map<String, Object>) obj;
            return maskMap(mapObj);
        }

        // Handle Lists directly
        if (obj instanceof List) {
            return maskList((List<?>) obj);
        }

        // Handle JsonNode
        if (obj instanceof JsonNode) {
            return maskJsonNode((JsonNode) obj);
        }

        // For complex objects, convert to Map and mask
        try {
            Map<String, Object> objectAsMap = convertObjectToMap(obj);
            return maskMap(objectAsMap);
        } catch (Exception e) {
            log.debug("Could not mask object of type {}: {}", obj.getClass().getName(), e.getMessage());
            return obj.toString();
        }
    }

    /**
     * Masks sensitive fields in a JsonNode.
     */
    private static JsonNode maskJsonNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return node;
        }

        if (node.isObject()) {
            ObjectNode masked = objectMapper.createObjectNode();
            node.fields().forEachRemaining(entry -> {
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if (isSensitive(key)) {
                    masked.put(key, MASK);
                } else if (value.isObject() || value.isArray()) {
                    masked.set(key, maskJsonNode(value));
                } else {
                    masked.set(key, value);
                }
            });
            return masked;
        }

        if (node.isArray()) {
            var masked = objectMapper.createArrayNode();
            for (JsonNode item : node) {
                masked.add(maskJsonNode(item));
            }
            return masked;
        }

        return node;
    }

    /**
     * Converts an object to a Map using reflection.
     */
    private static Map<String, Object> convertObjectToMap(Object obj) {
        Map<String, Object> map = new LinkedHashMap<>();
        Class<?> clazz = obj.getClass();

        // Get all fields including inherited ones
        List<Field> allFields = getAllFields(clazz);

        for (Field field : allFields) {
            field.setAccessible(true);
            try {
                String fieldName = field.getName();
                Object value = field.get(obj);
                map.put(fieldName, value);
            } catch (IllegalAccessException e) {
                log.debug("Could not access field {}: {}", field.getName(), e.getMessage());
            }
        }
        return map;
    }

    /**
     * Gets all fields from a class including inherited fields.
     */
    private static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        while (clazz != null && clazz != Object.class) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        return fields;
    }

    /**
     * Checks if an object is a complex type that needs deep masking.
     */
    private static boolean isComplexObject(Object obj) {
        if (obj == null) {
            return false;
        }
        Class<?> clazz = obj.getClass();
        return !clazz.isPrimitive()
                && !clazz.isEnum()
                && !(obj instanceof String)
                && !(obj instanceof Number)
                && !(obj instanceof Boolean)
                && !(obj instanceof Date)
                && !(obj instanceof UUID);
    }
}