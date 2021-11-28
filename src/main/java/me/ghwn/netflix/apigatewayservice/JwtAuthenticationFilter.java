package me.ghwn.netflix.apigatewayservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import me.ghwn.netflix.apigatewayservice.dto.RefreshTokenDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_TOKEN_PREFIX = "Bearer ";
    private static final String ACCOUNT_ID_PAYLOAD_KEY = "aid";
    private static final String ACCESS_TOKEN_HEADER_NAME = "access-token";
    private static final String REFRESH_TOKEN_HEADER_NAME = "refresh-token";
    private static final String ACCOUNT_ID_HEADER_NAME = "account-id";

    private final Environment env;
    private final WebClient webClient;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final String secret;
    private final Long accessExpirationTime;

    public JwtAuthenticationFilter(Environment env, WebClient webClient) {
        super(Config.class);
        this.env = env;
        this.webClient = webClient;

        this.secret = Objects.requireNonNull(env.getProperty("jwt.secret"));
        this.accessExpirationTime = Long.parseLong(Objects.requireNonNull(env.getProperty("jwt.access-token.expiration-time")));
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            // Check if request contains Authorization header.
            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();
            String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || authorization.isEmpty()) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Access token not found");
            }

            // Check if Authorization header is valid.
            if (!authorization.startsWith(BEARER_TOKEN_PREFIX)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Access token not valid");
            }

            // Extract access token
            String accessToken = authorization.substring(BEARER_TOKEN_PREFIX.length());

            // Check if access token is valid.
            SecretKey secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(this.secret));
            String accountId = null;
            try {
                accountId = Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody()
                        .get(ACCOUNT_ID_PAYLOAD_KEY, String.class);
            } catch (ExpiredJwtException e) {
                // If access token is expired, then find refresh token and re-issue new access token.
                String refreshToken = headers.getFirst(REFRESH_TOKEN_HEADER_NAME);
                if (refreshToken == null) {
                    return onError(exchange, HttpStatus.UNAUTHORIZED, "Access token is expired");
                }

                // Validate refresh token
                try {
                    Jwts.parserBuilder()
                            .setSigningKey(secretKey)
                            .build()
                            .parseClaimsJws(refreshToken);
                } catch (JwtException e2) {
                    return onError(exchange, HttpStatus.UNAUTHORIZED, "Refresh token not valid");
                }
                accountId = e.getClaims().get(ACCOUNT_ID_PAYLOAD_KEY, String.class);
                if (accountId == null) {
                    return onError(exchange, HttpStatus.UNAUTHORIZED, "Access token not valid");
                }

                String finalAccountId = accountId;
                return this.webClient.get()
                        .uri("http://127.0.0.1:8000/account-service/api/v1/accounts/{accountId}/refresh-token", accountId)
                        .retrieve()
                        .bodyToMono(RefreshTokenDto.class)
                        .flatMap(refreshTokenDto -> {
                            if (refreshTokenDto == null || refreshTokenDto.getValue() == null || !refreshTokenDto.getValue().equals(refreshToken)) {
                                return onError(exchange, HttpStatus.UNAUTHORIZED, "Refresh token not valid");
                            }

                            // Issue new access token and add it into the response header.
                            String newAccessToken = Jwts.builder()
                                    .setHeaderParam(Header.TYPE, "JWT")
                                    .claim(ACCOUNT_ID_PAYLOAD_KEY, finalAccountId)
                                    .setIssuedAt(new Date())
                                    .setExpiration(new Date(System.currentTimeMillis() + (this.accessExpirationTime * 1000)))
                                    .signWith(secretKey, SignatureAlgorithm.HS512)
                                    .compact();
                            exchange.getResponse().getHeaders().set(ACCESS_TOKEN_HEADER_NAME, newAccessToken);

                            exchange.getResponse().getHeaders().set(ACCOUNT_ID_HEADER_NAME, finalAccountId);
                            return chain.filter(exchange);
                        });

            } catch (JwtException e) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Access token not valid");
            }

            exchange.getResponse().getHeaders().set(ACCOUNT_ID_HEADER_NAME, accountId);
            return chain.filter(exchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus, String message) {
        logger.error(message);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        Map<String, String> error = new HashMap<>();
        error.put("error", message);
        String body = "";
        try {
            body = this.objectMapper.writeValueAsString(error);
        } catch (JsonProcessingException e) {
            body = "{\"error\": \"" + message + "\"}";
        }
        DataBuffer dataBuffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Flux.just(dataBuffer));
    }

    public static class Config {
    }

}
