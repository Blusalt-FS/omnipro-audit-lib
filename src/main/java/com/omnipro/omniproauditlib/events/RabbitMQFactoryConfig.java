package com.omnipro.omniproauditlib.events;

import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

@Configuration
public class RabbitMQFactoryConfig {


    @Value("${omnipro.audit-service.rabbit-url}")
    private String auditServiceRabbitUrl;

    @Value("${omnipro.audit-service.rabbit-userName}")
    private String auditServiceRabbitUsername;

    @Value("${omnipro.audit-service.rabbit-password}")
    private String auditServiceRabbitPassword;

    @Value("${spring.profiles.active}")
    private String profile;


    @Bean
    public Connection rabbitMQConnectionFactory() throws URISyntaxException, NoSuchAlgorithmException, KeyManagementException, IOException, TimeoutException {

        ConnectionFactory connectionFactory = new ConnectionFactory();
        String uri = auditServiceRabbitUrl;
        String username = auditServiceRabbitUsername;
        String password = auditServiceRabbitPassword;
        connectionFactory.setUri(uri);
        if (!Objects.equals(profile, "local")) {
            connectionFactory.setUsername(username);
            connectionFactory.setPassword(password);
        }
        return connectionFactory.newConnection();
    }

}
