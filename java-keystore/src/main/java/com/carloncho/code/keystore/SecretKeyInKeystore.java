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

import static com.carloncho.code.keystore.util.UtilKeyStore.*;


/**
 * Ejemplo de manejo de Secret key en Keystore
 * */
public class SecretKeyInKeystore {
	
	private static final Logger LOGGER = Logger.getLogger(SecretKeyInKeystore.class.getName());
	
	/**
	 * Se crea el archivo keystore. Si ya existe se carga con contraseña. Caso contrario se crea.
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * */
	public KeyStore crearKeystore(String nombreArchivoKeystore, String passwordArchivo) 
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
	 * @param keyStore
	 * @param keyPassword
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws KeyStoreException
	 */
	public SecretKey obtenerLlave(KeyStore keyStore, KeyStore.PasswordProtection keyPassword)
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
	public SecretKey generarLlave() throws NoSuchAlgorithmException, InvalidParameterException {
		
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
	public KeyStore.PasswordProtection almacenarSecretKey(KeyStore keyStore, SecretKey secretKey)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException {
		
		KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
		KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(LLAVE_PASSWORD.toCharArray());
		keyStore.setEntry(LLAVE, keyStoreEntry, keyPassword);
		keyStore.store(new FileOutputStream(ARCHIVO_KEY_STORE), FILE_PASSWORD.toCharArray());
		
		return keyPassword;
	}
	
}
