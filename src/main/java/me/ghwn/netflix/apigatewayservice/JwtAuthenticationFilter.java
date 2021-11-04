package me.ghwn.netflix.apigatewayservice;

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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String BEARER_TOKEN_PREFIX = "Bearer ";

    private final Environment env;

    @Autowired
    public JwtAuthenticationFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Extract Authorization header
            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();
            String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authorization == null || authorization.isEmpty()) {
                logger.error(String.format("Header does not contain %s", HttpHeaders.AUTHORIZATION));
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            // Valid JWT token
            String jwtToken = authorization.substring(BEARER_TOKEN_PREFIX.length());

            byte[] keyBytes = Decoders.BASE64.decode(env.getProperty("jwt.secret"));
            SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);

            String subject = null;
            try {
                subject = Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(jwtToken)
                        .getBody()
                        .getSubject();
            } catch (JwtException e) {
                logger.error(e.getMessage());
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            if (subject == null || subject.isEmpty()) {
                logger.error("JWT token is not valid");
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            logger.info("JWT authentication passed. (URI: {}, Subject: {})", request.getURI(), subject);

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    public static class Config {
    }
}
