package com.github.foamdino.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;

import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.stereotype.Component;

@Component
@OpenAPIDefinition(info = @Info(title = "Ecommerce example API", version = "v1"))
public class OpenApiConfig {
}
