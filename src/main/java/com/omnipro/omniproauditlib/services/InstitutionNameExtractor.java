package com.omnipro.omniproauditlib.services;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

public interface InstitutionNameExtractor {

    String getAuthenticatedUser();

    String getName();

    String getUserType();

    String getUserId();

    String extractInstitutionName(HttpServletRequest request);

    List<String> getMerchantIds(HttpServletRequest request);
}


