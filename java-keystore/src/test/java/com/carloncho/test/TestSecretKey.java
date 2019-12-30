package com.carloncho.test;

import static com.carloncho.code.keystore.util.UtilKeyStore.ARCHIVO_KEY_STORE;
import static com.carloncho.code.keystore.util.UtilKeyStore.FILE_PASSWORD;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import static org.assertj.core.api.Assertions.*;

import com.carloncho.code.keystore.SecretKeyInKeystore;
import com.carloncho.code.keystore.context.ApplicationConfiguration;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {ApplicationConfiguration.class})
//@TestPropertySource("classpath:test.properties")
public class TestSecretKey {

	private static final Logger LOGGER = Logger.getLogger(TestSecretKey.class.getName());
	
    @Autowired
    private SecretKeyInKeystore secretKeyInKeystoreService;
	
    
    @Test
    public void validarExistenciaKeyStore() {
    	
    	try {
    		
    		final KeyStore keyStore = secretKeyInKeystoreService.crearKeystore(ARCHIVO_KEY_STORE, FILE_PASSWORD);
    		File archivoKeystore = new File("keystoreDemo.jceks");
    		
    		LOGGER.debug("[keyStore]:" + keyStore.toString());
    		assertThat(archivoKeystore).exists().isFile().canRead();
    		
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
    }
    
    
}
