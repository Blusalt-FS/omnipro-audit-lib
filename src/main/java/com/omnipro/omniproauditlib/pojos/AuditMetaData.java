package com.omnipro.omniproauditlib.pojos;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class AuditMetaData {
    private String institutionName;
    private String institutionId;
    private String username;
    private String name;
    private String userType;
    private String userId;
    private List<String> merchantIds;
}
