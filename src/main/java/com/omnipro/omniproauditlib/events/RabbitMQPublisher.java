package com.omnipro.omniproauditlib.events;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import com.omnipro.omniproauditlib.dtos.AuditDto;
import java.io.IOException;
import java.nio.charset.Charset;

import static com.omnipro.omniproauditlib.Constant.RabbitMQ.*;


@Component
@Slf4j
public class RabbitMQPublisher {

    private final Channel channel;
    private final ObjectMapper mapper;

    public RabbitMQPublisher(Channel channel, @Qualifier("auditObjectMapper") ObjectMapper objectMapper) {
        this.channel = channel;
        this.mapper = objectMapper;
    }

    public void publishAuditEvent(AuditDto auditDto) {
        try {
            channel.exchangeDeclare(AUDIT_EXCHANGE_NAME, "direct", true);
            channel.queueDeclare(AUDIT_QUEUE_NAME, true, false, false, null);
            channel.queueBind(AUDIT_QUEUE_NAME, AUDIT_EXCHANGE_NAME, AUDIT_ROUTING_KEY);


            channel.basicPublish(AUDIT_EXCHANGE_NAME, AUDIT_ROUTING_KEY, null,
                    mapper.writeValueAsString(auditDto).getBytes(Charset.defaultCharset()));
            log.info(mapper.writeValueAsString(auditDto));
            log.info("Successfully published audit event");
        } catch (IOException ex) {
            log.error("Error publishing audit event");
        }
    }

    public void init() throws IOException {
        channel.exchangeDeclare(AUDIT_EXCHANGE_NAME, "direct", true);
        channel.queueDeclare(AUDIT_QUEUE_NAME, true, false, false, null);
        channel.queueBind(AUDIT_QUEUE_NAME, AUDIT_EXCHANGE_NAME, AUDIT_ROUTING_KEY);
        log.info("Queue successfully created");
    }
}
