package com.omnipro.omniproauditlib.config;

import com.omnipro.omniproauditlib.dtos.AuditMetadataExtractor;
import com.omnipro.omniproauditlib.pojos.AuditMetaData;
import com.omnipro.omniproauditlib.services.InstitutionNameExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Configuration
@RequiredArgsConstructor
public class AuditlibConfig {



    private final InstitutionNameExtractor institutionNameExtractor;

    @Bean
    public AuditMetadataExtractor auditMetadataExtractor() {
        return () -> {
            HttpServletRequest request =
                    ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
            String institutionName = institutionNameExtractor.extractInstitutionName(request);
            String userName = institutionNameExtractor.getAuthenticatedUser();

            return new AuditMetaData(institutionName,userName);
        };
    }
}

