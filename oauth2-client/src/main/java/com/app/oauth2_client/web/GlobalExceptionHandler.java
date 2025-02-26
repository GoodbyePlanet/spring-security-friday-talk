package com.app.oauth2_client.web;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(HttpClientErrorException.Forbidden.class)
    public String handleAccessDeniedException(HttpClientErrorException ex, Model model) {
        model.addAttribute("errorMessage", "You don't have enough permissions to access user contacts.");
        return "error/403";
    }

    @ExceptionHandler(HttpClientErrorException.class)
    public String handleHttpClientError(HttpClientErrorException ex, Model model) {
        model.addAttribute("errorMessage", "An error occurred: " + ex.getStatusCode());
        return "error/default";
    }
}
