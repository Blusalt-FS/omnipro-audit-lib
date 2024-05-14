package com.omnipro.omniproauditlib.pojos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuditMetaData {
    private String institutionName;
    private String username;
}
