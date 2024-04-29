package com.omnipro.omniproauditlib.aspects;

import com.omnipro.omniproauditlib.annotations.Audit;
import com.omnipro.omniproauditlib.dtos.AuditDto;
import com.omnipro.omniproauditlib.dtos.AuditMetadataExtractor;
import com.omnipro.omniproauditlib.pojos.AuditMetaData;
import com.omnipro.omniproauditlib.services.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;


import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLogger {

    @Value("${spring.application.name}")
    private String applicationName;
    private final HttpServletRequest httpServletRequest;
    private final AuditService auditService;
    private final AuditMetadataExtractor auditMetadataExtractor;

    @Around(value = "@annotation(com.omnipro.omniproauditlib.annotations.Audit)")
    public Object auditEventHandler(ProceedingJoinPoint joinPoint) throws Throwable {

        Signature methodSignature = joinPoint.getSignature();
        MethodSignature signature = (MethodSignature) methodSignature;
        Method method = joinPoint.getTarget().getClass()
                .getMethod(signature.getMethod().getName(), signature.getMethod().getParameterTypes());
        Object object [] = joinPoint.getArgs();
        Map<String, Object> request = new HashMap<>();
        for (int i = 0; i < object.length; i++) {
            request.put(signature.getParameterNames()[i], object[i].toString());
        }
        Date startTime = Date.from(Instant.now());
        // save Audit before method run
        AuditDto auditDto = new AuditDto();
        auditDto.setIpAddress(getClientIp(httpServletRequest));
        auditDto.setStartDate(startTime);
        auditDto.setApplication(applicationName);
        auditDto.setRequest(request);
        auditDto.setActivity(method.getAnnotation(Audit.class).activity());
        auditDto.setProcessId(UUID.randomUUID().toString());
        if (method.getAnnotation(Audit.class).isMetaDataRequired()) {
            AuditMetaData auditMetaData = auditMetadataExtractor.getAuditMetaData();
            auditDto.setInstitutionName(auditMetaData.getInstitutionName());
            auditDto.setUserId(auditMetaData.getUserId());
        }
        auditService.saveAudit(auditDto);
        Object proceed = joinPoint.proceed();
        //save audit after running using starttime for update
        auditDto.setResponseBody(proceed);
        auditService.saveAudit(auditDto);
        // end of activities
        return proceed;
    }

    private String getClientIp(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if(StringUtils.isEmpty(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }

        if(StringUtils.isEmpty(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }

        if(StringUtils.isEmpty(ipAddress) || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
            String LOCALHOST_IPV4 = "127.0.0.1";
            String LOCALHOST_IPV6 = "0:0:0:0:0:0:0:1";
            if(LOCALHOST_IPV4.equals(ipAddress) || LOCALHOST_IPV6.equals(ipAddress)) {
                try {
                    InetAddress inetAddress = InetAddress.getLocalHost();
                    ipAddress = inetAddress.getHostAddress();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                }
            }
        }

        if(!StringUtils.isEmpty(ipAddress)
                && ipAddress.length() > 15
                && ipAddress.indexOf(",") > 0) {
            ipAddress = ipAddress.substring(0, ipAddress.indexOf(","));
        }

        return ipAddress;
    }
}
