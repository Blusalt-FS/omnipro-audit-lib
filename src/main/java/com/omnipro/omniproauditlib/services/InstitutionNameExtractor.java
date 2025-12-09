package com.omnipro.omniproauditlib.services;

import jakarta.servlet.http.HttpServletRequest;

public interface InstitutionNameExtractor {

    String getAuthenticatedUser();

    String getName();

    String getUserType();

    String extractInstitutionName(HttpServletRequest request);
}


