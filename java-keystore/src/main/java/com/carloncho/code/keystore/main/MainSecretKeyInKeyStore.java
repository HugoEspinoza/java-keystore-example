
package com.carloncho.code.keystore.main;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import com.carloncho.code.keystore.SecretKeyInKeystore;
import com.carloncho.code.keystore.context.ApplicationConfiguration;

import static com.carloncho.code.keystore.util.UtilKeyStore.*;


/**
 * @author Administrador
 *
 */
public class MainSecretKeyInKeyStore {

	private static final Logger LOGGER = Logger.getLogger(MainSecretKeyInKeyStore.class.getName());
	
	/**
	 * Se crea/carga el Keystore, genera la llave, se almacena el secret key y se obtiene del keystore.
	 * */
	@SuppressWarnings("resource")
	public static void main(String[] args) {

        ApplicationContext context = new AnnotationConfigApplicationContext(ApplicationConfiguration.class);
        
        SecretKeyInKeystore secretKeyInKeystore = (SecretKeyInKeystore) context.getBean("secretKeyInKeystoreService");
 
		SecretKey keyFound = null;
				
		try {
			
			KeyStore keyStore = secretKeyInKeystore.crearKeystore(ARCHIVO_KEY_STORE, FILE_PASSWORD);
			
			SecretKey secretKey = secretKeyInKeystore.generarLlave();
			
			KeyStore.PasswordProtection keyPassword = secretKeyInKeystore.almacenarSecretKey(keyStore, secretKey);

			keyFound = secretKeyInKeystore.obtenerLlave(keyStore, keyPassword);
			
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableEntryException | InvalidParameterException excep) {

			LOGGER.error(excep);
			
		} finally {
			
			if(keyFound != null){
				LOGGER.info("Llave encontrada: " + keyFound.toString());
			}
		}
		
	}

}
