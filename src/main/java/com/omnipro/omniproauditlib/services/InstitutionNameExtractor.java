package com.omnipro.omniproauditlib.services;

import jakarta.servlet.http.HttpServletRequest;

public interface InstitutionNameExtractor {

    String getAuthenticatedUser();

    String extractInstitutionName(HttpServletRequest request);
}


