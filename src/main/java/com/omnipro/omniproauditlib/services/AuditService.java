package com.omnipro.omniproauditlib.services;

import com.omnipro.omniproauditlib.dtos.AuditDto;
import com.omnipro.omniproauditlib.events.RabbitMQPublisher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditService {


    private final RabbitMQPublisher rabbitMQPublisher;
    private static final ThreadLocal<String> contextHolder = new ThreadLocal<>();

    public void saveAudit(AuditDto auditDto) {
        rabbitMQPublisher.publishAuditEvent(auditDto);
    }
}
