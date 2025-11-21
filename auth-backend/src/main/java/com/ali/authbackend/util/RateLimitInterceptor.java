package com.ali.authbackend.util;

import com.ali.authbackend.annotation.RateLimit;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private final LoadingCache<String, Bucket> cache;

    public RateLimitInterceptor() {
        this.cache = CacheBuilder.newBuilder()
                .maximumSize(100000)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build(new CacheLoader<String, Bucket>() {
                    @Override
                    public Bucket load(String key) {
                        return createBucket(10, 10, 1);
                    }
                });
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            RateLimit rateLimit = handlerMethod.getMethodAnnotation(RateLimit.class);

            String key = request.getRemoteAddr();
            Bucket bucket;

            if (rateLimit != null) {
                String customKey = key + ":" + request.getRequestURI();
                bucket = cache.get(customKey, () -> createBucket(rateLimit.capacity(), rateLimit.refillTokens(), rateLimit.refillMinutes()));
            } else {
                bucket = cache.get(key, () -> createBucket(10, 10, 1));
            }

            ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

            if (probe.isConsumed()) {
                response.addHeader("X-Rate-Limit-Remaining", String.valueOf(probe.getRemainingTokens()));
                return true;
            }

            long waitForRefill = probe.getNanosToWaitForRefill() / 1_000_000_000;
            response.addHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(waitForRefill));
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), "Rate limit exceeded");
            return false;
        }

        return true;
    }

    private Bucket createBucket(int capacity, int refillTokens, int refillMinutes) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(capacity, Refill.intervally(refillTokens, Duration.ofMinutes(refillMinutes))))
                .build();
    }
}
