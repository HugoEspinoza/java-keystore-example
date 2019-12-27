package com.carloncho.code.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

/**
 * Ejemplo de manejo de Secret key en Keystore
 * */
public class SecretKeyInKeystore {

	private static final String TIPO_KEYSTORE_JCEKS = "JCEKS"; 				//Tipo de Keystore para almacenar llaves secretas
	private static final String ARCHIVO_KEY_STORE = "keystoreDemo.jceks"; 	//Nombre del archivo
	private static final String FILE_PASSWORD = "hola123"; 					//Password del archivo
	private static final String LLAVE = "llave3DES"; 						//Llave del entry para almacenar al keystore
	private static final String LLAVE_PASSWORD = "keyPassword"; 			//Password del entry almacenado
	private static final String ALGORITMO_AES = "AES"; 						//Algoritmo de encriptacion
	private static final Integer TAMANIO_LLAVE = 256; 						//Tamaños de llave: 64, 128, 256
	
	private static final Logger LOGGER = Logger.getLogger(SecretKeyInKeystore.class.getName());
	
	/**
	 * Se crea el archivo keystore. Si ya existe se carga con contraseña. Caso contrario se crea.
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * */
	private static KeyStore crearKeystore(String nombreArchivoKeystore, String passwordArchivo) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException  {
		
		File archivoKeystore = new File(nombreArchivoKeystore);
		final KeyStore keyStore = KeyStore.getInstance(TIPO_KEYSTORE_JCEKS);
		
		if (archivoKeystore.exists()) {
			
			keyStore.load(new FileInputStream(archivoKeystore), passwordArchivo.toCharArray());
			LOGGER.debug("Cargar keystore");
		} else {
			
			keyStore.load(null, null);
			keyStore.store(new FileOutputStream(nombreArchivoKeystore), passwordArchivo.toCharArray());
			LOGGER.debug("Crear keystore");
		}

		return keyStore;
	}
	
	
	/**
	 * Se crea/carga el Keystore, genera la llave, se almacena el secret key y se obtiene del keystore.
	 * */
	public static void main(String[] args) {

		SecretKey keyFound = null;
				
		try {
			
			KeyStore keyStore = crearKeystore(ARCHIVO_KEY_STORE, FILE_PASSWORD);
			
			SecretKey secretKey = generarLlave();
			
			KeyStore.PasswordProtection keyPassword = almacenarSecretKey(keyStore, secretKey);

			keyFound = obtenerLlave(keyStore, keyPassword);
			
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableEntryException | InvalidParameterException excep) {

			LOGGER.error(excep);
			
		} finally {
			
			if(keyFound != null){
				LOGGER.info("Llave encontrada: " + keyFound.toString());
			}
		}
		
	}

	
	/**
	 * @param keyStore
	 * @param keyPassword
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 */
	private static SecretKey obtenerLlave(KeyStore keyStore, KeyStore.PasswordProtection keyPassword)
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		
		KeyStore.Entry entry = keyStore.getEntry(LLAVE, keyPassword);
		SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
		return keyFound;
	}

	/**
	 * Generar un secret key con algoritmo AES
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static SecretKey generarLlave() throws NoSuchAlgorithmException, InvalidParameterException {
		
		KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO_AES);
		keyGen.init(TAMANIO_LLAVE); 
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}

	/**
	 * @param keyStore
	 * @param secretKey
	 * @return
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 */
	private static KeyStore.PasswordProtection almacenarSecretKey(KeyStore keyStore, SecretKey secretKey)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException {
		
		KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
		KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(LLAVE_PASSWORD.toCharArray());
		keyStore.setEntry(LLAVE, keyStoreEntry, keyPassword);
		keyStore.store(new FileOutputStream(ARCHIVO_KEY_STORE), FILE_PASSWORD.toCharArray());
		
		return keyPassword;
	}
	
}
