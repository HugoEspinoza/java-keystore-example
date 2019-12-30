package com.carloncho.code.keystore.context;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Description;

import com.carloncho.code.keystore.SecretKeyInKeystore;

@Configuration
@ComponentScan
public class ApplicationConfiguration {

	@Bean(name="secretKeyInKeystoreService")
	@Description("Para manejar secretKey")
	public SecretKeyInKeystore createSecretKeyInKeystore() {
		return new SecretKeyInKeystore();
	}
	
}
