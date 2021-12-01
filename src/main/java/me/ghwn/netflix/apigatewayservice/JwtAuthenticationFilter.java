package me.ghwn.netflix.apigatewayservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_TOKEN_PREFIX = "Bearer ";
    private static final String ACCOUNT_ID_PAYLOAD_KEY = "aid";

    private final Environment env;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public JwtAuthenticationFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            // Check if request contains Authorization header.
            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();
            String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || authorization.isEmpty()) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "No authorization header");
            }

            // Check if authorization type is bearer.
            if (!authorization.startsWith(BEARER_TOKEN_PREFIX)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Authorization type is not bearer");
            }

            // Extract access token
            String accessToken = authorization.substring(BEARER_TOKEN_PREFIX.length());

            // Check if access token is valid.
            String secret = this.env.getProperty("jwt.secret");
            if (!isValidAccessToken(accessToken, secret)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Access token is not valid");
            }

            return chain.filter(exchange);
        });
    }

    private boolean isValidAccessToken(String accessToken, String secret) {
        SecretKey secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        String accountId = null;
        try {
            accountId = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody()
                    .get(ACCOUNT_ID_PAYLOAD_KEY, String.class);
        } catch (JwtException e) {
            return false;
        }
        if (accountId == null || accountId.isEmpty()) {
            return false;
        }
        return true;
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
