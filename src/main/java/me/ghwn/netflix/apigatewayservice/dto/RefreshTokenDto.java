package me.ghwn.netflix.apigatewayservice.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter @Setter @NoArgsConstructor
public class RefreshTokenDto {

    private Long id;

    private String email;

    private String value;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}
