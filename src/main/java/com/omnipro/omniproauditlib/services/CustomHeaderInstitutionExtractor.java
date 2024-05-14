package com.omnipro.omniproauditlib.services;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Component
public class CustomHeaderInstitutionExtractor implements InstitutionNameExtractor {
    private static final Logger log = LoggerFactory.getLogger(CustomHeaderInstitutionExtractor.class);
    private static final List<String> HEADER_NAMES = Arrays.asList("institutionId", "Client-ID");



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
        else if (principal instanceof String) {
            email = (String) principal;
        }

        return email;
    }

    @Override
    public String extractInstitutionName(HttpServletRequest request) {
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
}