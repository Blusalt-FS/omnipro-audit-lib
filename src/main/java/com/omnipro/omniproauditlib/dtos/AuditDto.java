package com.omnipro.omniproauditlib.dtos;

import lombok.Data;

import jakarta.validation.constraints.*;
import java.util.Date;
import java.util.Map;

@Data
public class AuditDto {


    @NotBlank(message = "is required")
    private String ipAddress;

    @NotBlank(message = "is required")
    private String service;

    @NotBlank(message = "is required")
    private String institutionName;

    @NotNull(message = "is required")
    private Date startDate;

    @NotBlank(message = "is required")
    private String activity;
    private Map<String, Object> request;
    private Object responseBody;
    private String processId;
    private String userName;
}
