package test.liuzehua.securitydemo.jwt;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * JwtProperties
 *
 * @author lynn
 * @version 1.0.0
 * @date 2020/5/13 16:34
 */
@Component
@ConfigurationProperties(prefix = "jwt")
@Data
@ToString
public class JwtProperties {

    private String secretKey = "liuzehua";

    /** 验证时间：100年 */
    private long validityInMs = 86400000L;

    private String authHeader = "Authorization";

    private String headerPrefix = "Bearer ";

    private String home = "Bearer ";

//    @PostConstruct
//    public void init(){
//        System.out.println(new JwtProperties().toString());
//    }

}
