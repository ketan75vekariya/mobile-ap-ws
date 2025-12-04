package com.appsdeveloperblog.app.ws;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.appsdeveloperblog.app.ws.security.AppProperties;

@SpringBootApplication
public class MobileApWsApplication {

	public static void main(String[] args) {
		SpringApplication.run(MobileApWsApplication.class, args);
	}

    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
    
    @Bean(name="AppProperties")
	AppProperties getAppProperties()
	{
		return new AppProperties();
	}
    
    @Bean
    SpringApplicationContext springApplicationContext() {
    	return new SpringApplicationContext();
    }
    
    

}
