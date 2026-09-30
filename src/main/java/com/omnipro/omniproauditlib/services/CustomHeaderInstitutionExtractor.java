package com.omnipro.omniproauditlib.services;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Component
public class CustomHeaderInstitutionExtractor implements InstitutionNameExtractor {
    private static final Logger log = LoggerFactory.getLogger(CustomHeaderInstitutionExtractor.class);
    private static final List<String> HEADER_NAMES = Arrays.asList("institutionId", "Client-ID");
    private static final String PLATFORM_OWNER = "PLATFORM_OWNER";
    private static final Set<String> MERCHANT_USER_TYPES = Set.of("MERCHANT", "AGENT");
    private static final String CONTEXT_HEADER = "X-Context-Id";
    private static final ObjectMapper MAPPER = new ObjectMapper();



    @Override
    public String getAuthenticatedUser() {
        String email = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (Objects.isNull(principal)) {
            return email;
        }

        if(principal instanceof User) {
            User userDetail = (User) principal;
            email = userDetail.getUsername();
        }
        else if (principal instanceof Jwt) {
            String sub = ((Jwt) principal).getClaimAsString("sub");
            return sub != null ? sub : email;
        }
        else if (principal instanceof String) {
            email = (String) principal;
        }

        return email;
    }

    @Override
    public String getName() {
        String name = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (Objects.isNull(principal)) {
            return name;
        }
        if (principal instanceof Jwt) {
            String firstName = ((Jwt) principal).getClaimAsString("firstName");
            return firstName != null ? firstName : name;
        }
        return name;
    }

    @Override
    public String getUserType() {
        String userType = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (Objects.isNull(principal)) {
            return userType;
        }
        if (principal instanceof Jwt) {
            String type = ((Jwt) principal).getClaimAsString("userType");
            return type != null ? type : userType;
        }
        return userType;
    }

    @Override
    public String getUserId() {
        String userId = "";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (Objects.isNull(principal)) {
            return userId;
        }
        if (principal instanceof Jwt) {
            String id = ((Jwt) principal).getClaimAsString("userId");
            return id != null ? id : userId;
        }
        return userId;
    }

    /**
     * The institution an audit row belongs to. For end-user tokens this comes from the signed
     * institutionId claim so a caller can't file their activity under another institution by
     * spoofing a header. Headers are only trusted for platform owners (who act across
     * institutions) and non-JWT callers such as service-to-service or basic auth.
     */
    @Override
    public String extractInstitutionName(HttpServletRequest request) {
        Jwt jwt = currentJwt();
        if (jwt != null && !PLATFORM_OWNER.equalsIgnoreCase(jwt.getClaimAsString("userType"))) {
            String institutionId = jwt.getClaimAsString("institutionId");
            if (StringUtils.isNotEmpty(institutionId) && !"null".equalsIgnoreCase(institutionId)) {
                return institutionId;
            }
        }
        for (String header : HEADER_NAMES) {
            String value = request.getHeader(header);
            if (StringUtils.isNotEmpty(value)) {
                log.debug("Institution name found: {}", value);
                return value;
            }
        }
        log.warn("No institution name found in headers, defaulting to 'BluSalt'");
        return "BluSalt";
    }

    /**
     * The id of the institution an audit row belongs to — what the audit service scopes reads on.
     * Unlike {@link #extractInstitutionName}, this never falls back to the Client-ID header or the
     * "BluSalt" placeholder: an end-user token without an institution yields null rather than
     * anything the caller could influence. The institutionId header is only trusted for platform
     * owners and non-JWT callers.
     */
    @Override
    public String getInstitutionId(HttpServletRequest request) {
        Jwt jwt = currentJwt();
        if (jwt != null && !PLATFORM_OWNER.equalsIgnoreCase(jwt.getClaimAsString("userType"))) {
            String institutionId = jwt.getClaimAsString("institutionId");
            return StringUtils.isNotEmpty(institutionId) && !"null".equalsIgnoreCase(institutionId) ? institutionId : null;
        }
        String header = request != null ? request.getHeader(HEADER_NAMES.get(0)) : null;
        return StringUtils.isNotEmpty(header) ? header : null;
    }

    /**
     * The merchant(s) an audit row belongs to, for MERCHANT/AGENT users only. The active merchant
     * comes from the X-Context-Id header but is only accepted if it appears in the token's signed
     * merchantContexts claim (directly or as a business under a parent merchant). With no header,
     * a user tied to a single merchant is attributed to that merchant. Returns null otherwise.
     */
    @Override
    public List<String> getMerchantIds(HttpServletRequest request) {
        Jwt jwt = currentJwt();
        if (jwt == null || !MERCHANT_USER_TYPES.contains(String.valueOf(jwt.getClaimAsString("userType")).toUpperCase())) {
            return null;
        }
        List<Map<String, Object>> contexts = merchantContexts(jwt);
        if (contexts.isEmpty()) {
            return null;
        }

        String requested = request != null ? request.getHeader(CONTEXT_HEADER) : null;
        if (StringUtils.isNotEmpty(requested)) {
            return allowedMerchantIds(contexts).contains(requested) ? List.of(requested) : null;
        }
        if (contexts.size() == 1 && contexts.get(0).get("merchantId") != null) {
            return List.of(contexts.get(0).get("merchantId").toString());
        }
        return null;
    }

    private Jwt currentJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getPrincipal() instanceof Jwt jwt ? jwt : null;
    }

    private List<Map<String, Object>> merchantContexts(Jwt jwt) {
        Object raw = jwt.getClaims().get("merchantContexts");
        if (raw == null) {
            return List.of();
        }
        try {
            TypeReference<List<Map<String, Object>>> type = new TypeReference<>() {};
            return raw instanceof String json ? MAPPER.readValue(json, type) : MAPPER.convertValue(raw, type);
        } catch (Exception e) {
            log.warn("Unable to read merchantContexts claim: {}", e.getMessage());
            return List.of();
        }
    }

    private List<String> allowedMerchantIds(List<Map<String, Object>> contexts) {
        List<String> ids = new ArrayList<>();
        for (Map<String, Object> context : contexts) {
            if (context.get("merchantId") != null) {
                ids.add(context.get("merchantId").toString());
            }
            if (context.get("businesses") instanceof List<?> businesses) {
                for (Object business : businesses) {
                    if (business instanceof Map<?, ?> map && map.get("merchantId") != null) {
                        ids.add(map.get("merchantId").toString());
                    }
                }
            }
        }
        return ids;
    }
}
