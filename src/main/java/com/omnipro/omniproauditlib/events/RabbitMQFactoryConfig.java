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

    @Value("${omnipro.audit-service.url}")
    private String auditServiceUrl;

    @Value("${spring.profiles.active}")
    private String profile;
    RestTemplate restTemplate = new RestTemplate();


    @Bean
    public Connection rabbitMQConnectionFactory()
            throws URISyntaxException, NoSuchAlgorithmException, KeyManagementException, IOException, TimeoutException {
        Map<String, Object> map = restTemplate.getForObject(auditServiceUrl + "/clients/rabbitmq-uri", Map.class);
        ConnectionFactory connectionFactory = new ConnectionFactory();
        Map<String, String> data = (Map<String, String>) map.get("data");
        String uri = data.get("uri");
        String username = data.get("username");
        String password = data.get("password");
        connectionFactory.setUri(uri);
        if (!Objects.equals(profile, "local")) {
            connectionFactory.setUsername(username);
            connectionFactory.setPassword(password);
        }
        return connectionFactory.newConnection();
    }

}
