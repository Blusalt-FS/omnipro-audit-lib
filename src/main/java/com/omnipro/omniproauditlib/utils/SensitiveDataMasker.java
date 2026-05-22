package com.omnipro.omniproauditlib.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;

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
    private static final int MAX_DEPTH = 10;
    private static final String CIRCULAR_REF = "[circular reference]";
    private static final String MAX_DEPTH_MSG = "[max depth exceeded]";

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

    // Types that should not be traversed (framework/infrastructure types)
    private static final Set<String> SKIP_TYPE_PATTERNS = Set.of(
            "org.springframework.http.",
            "org.springframework.web.",
            "jakarta.servlet.",
            "javax.servlet.",
            "org.apache.catalina.",
            "org.apache.coyote.",
            "org.apache.tomcat.",
            "java.io.InputStream",
            "java.io.OutputStream",
            "java.nio.",
            "sun.",
            "com.sun."
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
        return maskMap(data, new IdentityHashMap<>(), 0);
    }

    private static Map<String, Object> maskMap(Map<String, Object> data, IdentityHashMap<Object, Boolean> visited, int depth) {
        if (data == null || depth > MAX_DEPTH) {
            return data == null ? null : Map.of("_info", MAX_DEPTH_MSG);
        }

        // Check for circular reference
        if (visited.containsKey(data)) {
            return Map.of("_info", CIRCULAR_REF);
        }
        visited.put(data, Boolean.TRUE);

        Map<String, Object> masked = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (isSensitive(key)) {
                masked.put(key, MASK);
            } else if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                masked.put(key, maskMap(nestedMap, visited, depth + 1));
            } else if (value instanceof List) {
                masked.put(key, maskList((List<?>) value, visited, depth + 1));
            } else if (value != null && isComplexObject(value)) {
                masked.put(key, maskObjectInternal(value, visited, depth + 1));
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
        return maskList(data, new IdentityHashMap<>(), 0);
    }

    private static List<Object> maskList(List<?> data, IdentityHashMap<Object, Boolean> visited, int depth) {
        if (data == null) {
            return null;
        }
        if (depth > MAX_DEPTH) {
            return List.of(MAX_DEPTH_MSG);
        }

        if (visited.containsKey(data)) {
            return List.of(CIRCULAR_REF);
        }
        visited.put(data, Boolean.TRUE);

        List<Object> masked = new ArrayList<>();
        for (Object item : data) {
            if (item instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> mapItem = (Map<String, Object>) item;
                masked.add(maskMap(mapItem, visited, depth + 1));
            } else if (item instanceof List) {
                masked.add(maskList((List<?>) item, visited, depth + 1));
            } else if (item != null && isComplexObject(item)) {
                masked.add(maskObjectInternal(item, visited, depth + 1));
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
        return maskObjectInternal(obj, new IdentityHashMap<>(), 0);
    }

    /**
     * Builds a mutable two-entry map that tolerates null values.
     * Unlike {@link Map#of}, this does not throw on null keys or values,
     * which is required for void/empty responses (e.g. {@code ResponseEntity}
     * with a null body).
     */
    private static Map<String, Object> nullSafeMap(String key1, Object value1, String key2, Object value2) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put(key1, value1);
        map.put(key2, value2);
        return map;
    }

    private static Object maskObjectInternal(Object obj, IdentityHashMap<Object, Boolean> visited, int depth) {
        if (obj == null) {
            return null;
        }

        // Depth limit check
        if (depth > MAX_DEPTH) {
            return MAX_DEPTH_MSG;
        }

        // Check for circular reference
        if (visited.containsKey(obj)) {
            return CIRCULAR_REF;
        }

        // Handle primitives and common types (no tracking needed)
        if (obj instanceof String || obj instanceof Number || obj instanceof Boolean) {
            return obj;
        }

        // Handle ResponseEntity specially - extract and mask the body
        if (obj instanceof ResponseEntity<?> responseEntity) {
            Object body = responseEntity.getBody();
            Object maskedBody = (body == null) ? null : maskObjectInternal(body, visited, depth + 1);
            return nullSafeMap(
                "status", responseEntity.getStatusCode().value(),
                "body", maskedBody
            );
        }

        // Skip framework types that cause issues
        if (shouldSkipType(obj.getClass())) {
            return obj.getClass().getSimpleName() + "[skipped]";
        }

        // Mark as visited
        visited.put(obj, Boolean.TRUE);

        // Handle Maps directly
        if (obj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> mapObj = (Map<String, Object>) obj;
            return maskMap(mapObj, visited, depth);
        }

        // Handle Lists directly
        if (obj instanceof List) {
            return maskList((List<?>) obj, visited, depth);
        }

        // Handle JsonNode
        if (obj instanceof JsonNode) {
            return maskJsonNode((JsonNode) obj);
        }

        // For complex objects, convert to Map and mask
        try {
            Map<String, Object> objectAsMap = convertObjectToMap(obj, visited, depth);
            return maskMap(objectAsMap, visited, depth);
        } catch (Exception e) {
            log.debug("Could not mask object of type {}: {}", obj.getClass().getName(), e.getMessage());
            return obj.getClass().getSimpleName() + "[unmasked]";
        }
    }

    /**
     * Checks if a type should be skipped (framework/infrastructure types).
     */
    private static boolean shouldSkipType(Class<?> clazz) {
        String className = clazz.getName();
        return SKIP_TYPE_PATTERNS.stream().anyMatch(className::startsWith);
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
    private static Map<String, Object> convertObjectToMap(Object obj, IdentityHashMap<Object, Boolean> visited, int depth) {
        Map<String, Object> map = new LinkedHashMap<>();
        Class<?> clazz = obj.getClass();

        // Get all fields including inherited ones
        List<Field> allFields = getAllFields(clazz);

        for (Field field : allFields) {
            // Skip synthetic fields (generated by compiler)
            if (field.isSynthetic()) {
                continue;
            }

            field.setAccessible(true);
            try {
                String fieldName = field.getName();
                Object value = field.get(obj);

                // Skip if field type should be skipped
                if (value != null && shouldSkipType(value.getClass())) {
                    map.put(fieldName, value.getClass().getSimpleName() + "[skipped]");
                    continue;
                }

                // Mask sensitive field names immediately
                if (isSensitive(fieldName)) {
                    map.put(fieldName, MASK);
                } else {
                    map.put(fieldName, value);
                }
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
