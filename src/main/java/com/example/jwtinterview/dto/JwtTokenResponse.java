package com.example.jwtinterview.dto;

import com.example.jwtinterview.entity.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtTokenResponse {
    private String accessToken;
    private String token;
}
