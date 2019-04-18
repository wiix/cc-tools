package net.cccode.tools.crypto;

/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <dweymouth@gmail.com> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return. D. Weymouth 4/2014
 * ----------------------------------------------------------------------------
 */

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32InputStream;
import org.apache.commons.codec.binary.Base32OutputStream;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A class to perform password-based AES encryption and decryption in CBC mode.
 * 128, 192, and 256-bit encryption are supported, provided that the latter two
 * are permitted by the Java runtime's jurisdiction policy files.
 * <br/>
 * The public interface for this class consists of the static methods
 * {@link #encrypt} and {@link #decrypt}, which encrypt and decrypt arbitrary
 * streams of data, respectively.
 */

/**
 * 解决了输入输出流未关闭引起的信息不完整的bug。
 * 添加了字节和字符串的处理。
 * 添加了无密码验证的加密/解密版本
 * 
 * @author CC - cccode@outlook.com
 * @since 2015年11月26日 下午4:56:39
 * @version V1.0
 * 
 */
public final class AESTools {

	//private static final Logger logger = Logger.getLogger(AESTools.class);
	private static final Log logger = LogFactory.getLog(AESTools.class);

	// AES specification - changing will break existing encrypted streams!
	private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";//"算法/模式/补码方式"
	//AES/CBC/ISO10126Padding   CryptoJS v3.1.2
	//算法/模式/填充                16字节加密后数据长度        不满16字节加密后长度
	//AES/CBC/NoPadding             16                          不支持
	//AES/CBC/PKCS5Padding          32                          16
	//AES/CBC/ISO10126Padding       32                          16
	//AES/CFB/NoPadding             16                          原始数据长度
	//AES/CFB/PKCS5Padding          32                          16
	//AES/CFB/ISO10126Padding       32                          16
	//AES/ECB/NoPadding             16                          不支持
	//AES/ECB/PKCS5Padding          32                          16
	//AES/ECB/ISO10126Padding       32                          16
	//AES/OFB/NoPadding             16                          原始数据长度
	//AES/OFB/PKCS5Padding          32                          16
	//AES/OFB/ISO10126Padding       32                          16
	//AES/PCBC/NoPadding            16                          不支持
	//AES/PCBC/PKCS5Padding         32                          16
	//AES/PCBC/ISO10126Padding      32                          16
	// 
	// 
	// 
	//CryptoJS supports the following padding schemes:
	// 
	//	    Pkcs7 (the default)
	//	    Iso97971
	//	    AnsiX923
	//	    Iso10126
	//	    ZeroPadding
	//	    NoPadding 

	// Key derivation specification - changing will break existing streams!
	//	AES           Constructs secret keys for use with the AES algorithm. 
	//	ARCFOUR       Constructs secret keys for use with the ARCFOUR algorithm. 
	//	DES           Constructs secrets keys for use with the DES algorithm. 
	//	DESede        Constructs secrets keys for use with the DESede (Triple-DES) algorithm. 
	//
	//	PBEWith<digest>And<encryption>
	//	PBEWith<prf>And<encryption>
	//	Secret-key factory for use with PKCS5 password-based encryption, where <digest> is a message digest, <prf> is a pseudo-random function, and <encryption> is an encryption algorithm. 
	//	Examples:
	//	PBEWithMD5AndDES (PKCS5, v 1.5),
	//	PBEWithHmacSHA1AndDESede (PKCS5, v 2.0), and
	//	Note: These all use only the low order 8 bits of each password character.
	//
	//	PBKDF2WithHmacSHA1       Constructs secret keys using the Password-Based Key Derivation Function function found in PKCS #5 v2.0. 
	private static final String KEYGEN_SPEC = "PBKDF2WithHmacSHA1";
	private static final int SALT_LENGTH = 32; // in bytes
	private static final int AUTH_KEY_LENGTH = 16; // in bytes
	private static final int ITERATIONS = 32768;

	// Process input/output streams in chunks - arbitrary
	private static final int BUFFER_SIZE = 1024;


	/**
	 * @return a new pseudorandom salt of the specified length
	 */
	private static byte[] generateSalt(int length) {
		//		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		Random r = new SecureRandom();

		byte[] salt = new byte[length];
		r.nextBytes(salt);
		return salt;
	}


	/**
	 * Derive an AES encryption key and authentication key from given password
	 * and salt,
	 * using PBKDF2 key stretching. The authentication key is 64 bits long.
	 * PBE——Password-based encryption（基于密码加密）。
	 * 其特点在于口令由用户自己掌管，不借助任何物理媒体；采用随机数（盐）杂凑多重加密等方法保证数据的安全性。
	 * 
	 * @param keyLength
	 *            length of the AES key in bits (128, 192, or 256)
	 * @param password
	 *            the password from which to derive the keys
	 * @param salt
	 *            the salt from which to derive the keys
	 * @return a Keys object containing the two generated keys
	 */
	private static Keys generatekey(int keyLength, char[] password, byte[] salt) {
		SecretKeyFactory factory;
		try {
			factory = SecretKeyFactory.getInstance(KEYGEN_SPEC);
		} catch (NoSuchAlgorithmException impossible) {
			return null;
		}
		// derive a longer key, then split into AES key and authentication key
		KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, keyLength + AUTH_KEY_LENGTH * 8);
		SecretKey tmp = null;
		try {
			tmp = factory.generateSecret(spec);
		} catch (InvalidKeySpecException impossible) {
		}
		byte[] fullKey = tmp.getEncoded();
		SecretKey authKey = new SecretKeySpec( // key for password authentication
				Arrays.copyOfRange(fullKey, 0, AUTH_KEY_LENGTH), "AES");
		SecretKey encKey = new SecretKeySpec( // key for AES encryption
				Arrays.copyOfRange(fullKey, AUTH_KEY_LENGTH, fullKey.length), "AES");
		return new Keys(encKey, authKey);
	}


	/**
	 * Derive an AES encryption key and authentication key from given password
	 * and salt,
	 * using PBKDF2 key stretching. The authentication key is 64 bits long.
	 * PBE——Password-based encryption（基于密码加密）。
	 * 其特点在于口令由用户自己掌管，不借助任何物理媒体；采用随机数（盐）杂凑多重加密等方法保证数据的安全性。
	 * 无密码认证版本
	 * 
	 * @param keyLength
	 *            length of the AES key in bits (128, 192, or 256)
	 * @param password
	 *            the password from which to derive the keys
	 * @param salt
	 *            the salt from which to derive the keys
	 * @return SecretKeySpec Key
	 */
	private static SecretKeySpec genkey(int keyLength, char[] password, byte[] salt) {
		SecretKeyFactory factory;
		try {
			factory = SecretKeyFactory.getInstance(KEYGEN_SPEC);
		} catch (NoSuchAlgorithmException impossible) {
			return null;
		}
		// derive a longer key, then split into AES key and authentication key
		KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, keyLength);
		SecretKey secretKey = null;
		try {
			secretKey = factory.generateSecret(spec);
		} catch (InvalidKeySpecException impossible) {
		}
		return new SecretKeySpec(secretKey.getEncoded(), "AES");
	}


	/**
	 * Encrypts a stream of data. The encrypted stream consists of a header
	 * followed by the raw AES data. The header is broken down as follows:<br/>
	 * 无密码认证版本
	 * 
	 * <ul>
	 * <li><b>keyLength</b>: AES key length in bytes (valid for 16, 24, 32) (1
	 * byte)</li>
	 * <li><b>salt</b>: pseudorandom salt used to derive keys from password (16
	 * bytes)</li>
	 * <li><b>authentication key</b> (derived from password and salt, used to
	 * check validity of password upon decryption) (8 bytes)</li>
	 * <li><b>IV</b>: pseudorandom AES initialization vector (16 bytes)</li>
	 * </ul>
	 * 
	 * @param keyLength
	 *            key length to use for AES encryption (must be 128, 192, or
	 *            256)
	 * @param password
	 *            password to use for encryption
	 * @param input
	 *            an arbitrary byte stream to encrypt
	 * @param output
	 *            stream to which encrypted data will be written
	 * @throws AESTools.InvalidKeyLengthException
	 *             if keyLength is not 128, 192, or 256
	 * @throws AESTools.StrongEncryptionNotAvailableException
	 *             if keyLength is 192 or 256, but the Java runtime's
	 *             jurisdiction
	 *             policy files do not allow 192- or 256-bit encryption
	 * @throws IOException
	 */
	public static void encrypt2(int keyLength, char[] password, InputStream input, OutputStream output)
			throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException {
		// Check validity of key length
		if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
			throw new InvalidKeyLengthException(keyLength);
		}

		// generate salt and derive keys for authentication and encryption
		byte[] salt = generateSalt(SALT_LENGTH);
		SecretKeySpec key = genkey(keyLength, password, salt);

		// initialize AES encryption
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(CIPHER_SPEC);
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException impossible) {
		} catch (InvalidKeyException e) { // 192 or 256-bit AES not available
			throw new StrongEncryptionNotAvailableException(keyLength);
		}

		// get initialization vector
		byte[] iv = null;
		try {
			iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
		} catch (InvalidParameterSpecException impossible) {
		}

		// write authentication and AES initialization data
		output.write(keyLength / 8);
		output.write(salt);
		output.write(iv);

		// read data from input into buffer, encrypt and write to output
		byte[] buffer = new byte[BUFFER_SIZE];
		int numRead;
		byte[] encrypted = null;
		while ((numRead = input.read(buffer)) > 0) {
			logger.debug("numRead:" + numRead);
			encrypted = cipher.update(buffer, 0, numRead);
			if (encrypted != null) {
				logger.debug("encrypted.length:" + encrypted.length);
				output.write(encrypted);
			}
		}
		try { // finish encryption - do final block
			encrypted = cipher.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException impossible) {
		}
		if (encrypted != null) {
			logger.debug("encrypted.length:" + encrypted.length);
			output.write(encrypted);
		}
		output.flush();
		output.close();
		input.close();
	}


	/**
	 * Decrypts a stream of data that was encrypted by {@link #encrypt}.
	 * 无密码认证版本
	 * 
	 * @param password
	 *            the password used to encrypt/decrypt the stream
	 * @param input
	 *            stream of encrypted data to be decrypted
	 * @param output
	 *            stream to which decrypted data will be written
	 * @return the key length for the decrypted stream (128, 192, or 256)
	 * @throws AESTools.InvalidPasswordException
	 *             if the given password was not used to encrypt the data
	 * @throws AESTools.InvalidAESStreamException
	 *             if the given input stream is not a valid AES-encrypted stream
	 * @throws AESTools.StrongEncryptionNotAvailableException
	 *             if the stream is 192 or 256-bit encrypted, and the Java
	 *             runtime's
	 *             jurisdiction policy files do not allow for AES-192 or 256
	 * @throws IOException
	 */
	public static int decrypt2(char[] password, InputStream input, OutputStream output)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		int keyLength = input.read() * 8;
		// Check validity of key length
		if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
			throw new InvalidAESStreamException();
		}

		// read salt, generate keys, and authenticate password
		byte[] salt = new byte[SALT_LENGTH];
		input.read(salt);
		SecretKeySpec key = genkey(keyLength, password, salt);

		// initialize AES decryption
		byte[] iv = new byte[16]; // 16-byte I.V. regardless of key size
		input.read(iv);
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(CIPHER_SPEC);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException impossible) {
		} catch (InvalidKeyException e) { // 192 or 256-bit AES not available
			throw new StrongEncryptionNotAvailableException(keyLength);
		}

		// read data from input into buffer, decrypt and write to output
		byte[] buffer = new byte[BUFFER_SIZE];
		int numRead;
		byte[] decrypted;
		while ((numRead = input.read(buffer)) > 0) {
			logger.debug("numRead:" + numRead);
			decrypted = cipher.update(buffer, 0, numRead);
			if (decrypted != null) {
				logger.debug("decrypted.length:" + decrypted.length);
				output.write(decrypted);
			}
		}
		try { // finish decryption - do final block
			decrypted = cipher.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new InvalidAESStreamException(e);
		}
		if (decrypted != null) {
			logger.debug("decrypted.length:" + decrypted.length);
			output.write(decrypted);
		}
		output.flush();
		output.close();
		input.close();
		return keyLength;
	}


	/**
	 * Encrypts a stream of data. The encrypted stream consists of a header
	 * followed by the raw AES data. The header is broken down as follows:<br/>
	 * <ul>
	 * <li><b>keyLength</b>: AES key length in bytes (valid for 16, 24, 32) (1
	 * byte)</li>
	 * <li><b>salt</b>: pseudorandom salt used to derive keys from password (16
	 * bytes)</li>
	 * <li><b>authentication key</b> (derived from password and salt, used to
	 * check validity of password upon decryption) (8 bytes)</li>
	 * <li><b>IV</b>: pseudorandom AES initialization vector (16 bytes)</li>
	 * </ul>
	 * 
	 * @param keyLength
	 *            key length to use for AES encryption (must be 128, 192, or
	 *            256)
	 * @param password
	 *            password to use for encryption
	 * @param input
	 *            an arbitrary byte stream to encrypt
	 * @param output
	 *            stream to which encrypted data will be written
	 * @throws AESTools.InvalidKeyLengthException
	 *             if keyLength is not 128, 192, or 256
	 * @throws AESTools.StrongEncryptionNotAvailableException
	 *             if keyLength is 192 or 256, but the Java runtime's
	 *             jurisdiction
	 *             policy files do not allow 192- or 256-bit encryption
	 * @throws IOException
	 */
	public static void encrypt(int keyLength, char[] password, InputStream input, OutputStream output)
			throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException {
		// Check validity of key length
		if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
			throw new InvalidKeyLengthException(keyLength);
		}

		// generate salt and derive keys for authentication and encryption
		byte[] salt = generateSalt(SALT_LENGTH);
		Keys keys = generatekey(keyLength, password, salt);

		// initialize AES encryption
		Cipher encrypt = null;
		try {
			encrypt = Cipher.getInstance(CIPHER_SPEC);
			encrypt.init(Cipher.ENCRYPT_MODE, keys.encryption);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException impossible) {
		} catch (InvalidKeyException e) { // 192 or 256-bit AES not available
			throw new StrongEncryptionNotAvailableException(keyLength);
		}

		// get initialization vector
		byte[] iv = null;
		try {
			iv = encrypt.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
		} catch (InvalidParameterSpecException impossible) {
		}

		// write authentication and AES initialization data
		output.write(keyLength / 8);
		output.write(salt);
		output.write(keys.authentication.getEncoded());
		output.write(iv);

		// read data from input into buffer, encrypt and write to output
		byte[] buffer = new byte[BUFFER_SIZE];
		int numRead;
		byte[] encrypted = null;
		while ((numRead = input.read(buffer)) > 0) {
			logger.debug("numRead:" + numRead);
			encrypted = encrypt.update(buffer, 0, numRead);
			if (encrypted != null) {
				logger.debug("encrypted.length:" + encrypted.length);
				output.write(encrypted);
			}
		}
		try { // finish encryption - do final block
			encrypted = encrypt.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException impossible) {
		}
		if (encrypted != null) {
			logger.debug("encrypted.length:" + encrypted.length);
			output.write(encrypted);
		}
		output.flush();
		output.close();
		input.close();
	}


	/**
	 * Decrypts a stream of data that was encrypted by {@link #encrypt}.
	 * 
	 * @param password
	 *            the password used to encrypt/decrypt the stream
	 * @param input
	 *            stream of encrypted data to be decrypted
	 * @param output
	 *            stream to which decrypted data will be written
	 * @return the key length for the decrypted stream (128, 192, or 256)
	 * @throws AESTools.InvalidPasswordException
	 *             if the given password was not used to encrypt the data
	 * @throws AESTools.InvalidAESStreamException
	 *             if the given input stream is not a valid AES-encrypted stream
	 * @throws AESTools.StrongEncryptionNotAvailableException
	 *             if the stream is 192 or 256-bit encrypted, and the Java
	 *             runtime's
	 *             jurisdiction policy files do not allow for AES-192 or 256
	 * @throws IOException
	 */
	public static int decrypt(char[] password, InputStream input, OutputStream output)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		int keyLength = input.read() * 8;
		// Check validity of key length
		if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
			throw new InvalidAESStreamException();
		}

		// read salt, generate keys, and authenticate password
		byte[] salt = new byte[SALT_LENGTH];
		input.read(salt);
		Keys keys = generatekey(keyLength, password, salt);
		byte[] authRead = new byte[AUTH_KEY_LENGTH];
		input.read(authRead);
		if (!Arrays.equals(keys.authentication.getEncoded(), authRead)) {
			throw new InvalidPasswordException();
		}

		// initialize AES decryption
		byte[] iv = new byte[16]; // 16-byte I.V. regardless of key size
		input.read(iv);
		Cipher decrypt = null;
		try {
			decrypt = Cipher.getInstance(CIPHER_SPEC);
			decrypt.init(Cipher.DECRYPT_MODE, keys.encryption, new IvParameterSpec(iv));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException impossible) {
		} catch (InvalidKeyException e) { // 192 or 256-bit AES not available
			throw new StrongEncryptionNotAvailableException(keyLength);
		}

		// read data from input into buffer, decrypt and write to output
		byte[] buffer = new byte[BUFFER_SIZE];
		int numRead;
		byte[] decrypted;
		while ((numRead = input.read(buffer)) > 0) {
			logger.debug("numRead:" + numRead);
			decrypted = decrypt.update(buffer, 0, numRead);
			if (decrypted != null) {
				logger.debug("decrypted.length:" + decrypted.length);
				output.write(decrypted);
			}
		}
		try { // finish decryption - do final block
			decrypted = decrypt.doFinal();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new InvalidAESStreamException(e);
		}
		if (decrypted != null) {
			logger.debug("decrypted.length:" + decrypted.length);
			output.write(decrypted);
		}
		output.flush();
		output.close();
		input.close();
		return keyLength;
	}


	public static byte[] SHADigest(InputStream input, String algorithm) {
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
		}
		byte[] buffer = new byte[BUFFER_SIZE];
		int numRead;
		try {
			while ((numRead = input.read(buffer)) > 0) {
				digest.update(buffer, 0, numRead);
			}
		} catch (IOException e) {
		}
		byte[] res = digest.digest();
		return res;
	}


	public static byte[] SHADigest(String input, String charsetName, String algorithm) throws UnsupportedEncodingException {
		byte[] buffer = input.getBytes(charsetName);//"ISO8859-1"
		return SHADigest(new ByteArrayInputStream(buffer), algorithm);
	}


	public static byte[] SHA1Digest(InputStream input) {
		return SHADigest(input, "SHA-1");
	}


	public static byte[] SHA256Digest(String input) {
		try {
			return SHADigest(input, "ISO8859-1", "SHA-256");
		} catch (UnsupportedEncodingException e) {
		}
		return null;
	}


	public static String toHexString(byte[] input) {
		StringBuilder strHexString = new StringBuilder();
		for (int i = 0; i < input.length; i++) {
			String hex = Integer.toHexString(0xff & input[i]);
			if (hex.length() == 1) {
				strHexString.append('0');
			}
			strHexString.append(hex);
		}
		return strHexString.toString();
	}


	public static String getSHA256Digest(String input) {
		return toHexString(SHA256Digest(input));
	}


	public static byte[] readStreamBytes(InputStream inputStream) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		BufferedInputStream bis = null;
		try {
			bis = new BufferedInputStream(inputStream);
			byte[] buffer = new byte[4096];
			int readLength = 0;
			while ((readLength = bis.read(buffer)) > 0) {
				baos.write(buffer, 0, readLength);
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				baos.flush();
				baos.close();
				if (bis != null) {
					bis.close();
				}
			} catch (IOException e) {
			}
		}
		byte[] data = baos.toByteArray();
		return data;
	}


	public static void writeByteArrayToFile(File file, byte[] data) throws IOException {
		writeByteArrayToFile(file, data, false);
	}


	/**
	 * Writes a byte array to a file creating the file if it does not exist.
	 * 
	 * @param file the file to write to
	 * @param data the content to write to the file
	 * @param append if {@code true}, then bytes will be added to the
	 *            end of the file rather than overwriting
	 * @throws IOException in case of an I/O error
	 * @since IO 2.1
	 */
	public static void writeByteArrayToFile(File file, byte[] data, boolean append) throws IOException {
		OutputStream out = null;
		try {
			out = openOutputStream(file, append);
			out.write(data);
			out.close(); // don't swallow close Exception if copy completes normally
		} finally {
			closeQuietly(out);
		}
	}


	public static FileOutputStream openOutputStream(File file, boolean append) throws IOException {
		if (file.exists()) {
			if (file.isDirectory()) {
				throw new IOException("File '" + file + "' exists but is a directory");
			}
			if (file.canWrite() == false) {
				throw new IOException("File '" + file + "' cannot be written to");
			}
		} else {
			File parent = file.getParentFile();
			if (parent != null) {
				if (!parent.mkdirs() && !parent.isDirectory()) {
					throw new IOException("Directory '" + parent + "' could not be created");
				}
			}
		}
		return new FileOutputStream(file, append);
	}


	public static void closeQuietly(OutputStream output) {
		closeQuietly((Closeable) output);
	}


	public static void closeQuietly(Closeable closeable) {
		try {
			if (closeable != null) {
				closeable.close();
			}
		} catch (IOException ioe) {
			// ignore
		}
	}


	public static byte[] encrypt(int keyLength, char[] password, byte[] input)
			throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException {
		BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(input));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		encrypt(keyLength, password, is, baos);
		baos.flush();
		return baos.toByteArray();
	}


	public static byte[] decrypt(char[] password, byte[] input)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(input));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		decrypt(password, is, baos);
		baos.flush();
		return baos.toByteArray();
	}


	public static byte[] encryptB64(int keyLength, char[] password, byte[] input)
			throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException {
		//BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(getBytes(input.toCharArray())));
		BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(input));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Base64OutputStream b64os = new Base64OutputStream(baos, true, 0, null);
		encrypt(keyLength, password, is, b64os);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return baos.toByteArray();
	}


	public static byte[] decryptB64(char[] password, byte[] input)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		//		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(getBytes(input.toCharArray())), false);
		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(input), false);

		BufferedInputStream is = new BufferedInputStream(b64os);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		decrypt(password, is, baos);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return baos.toByteArray();
	}


	public static byte[] decryptB64(char[] password, byte[] input, int offset, int length)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		//		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(getBytes(input.toCharArray())), false);
		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(input, offset, length), false);

		BufferedInputStream is = new BufferedInputStream(b64os);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		decrypt(password, is, baos);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return baos.toByteArray();
	}


	public static String encrypt(int keyLength, char[] password, String input)
			throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException {
		//BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(getBytes(input.toCharArray())));
		BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(input.getBytes("UTF-8")));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Base64OutputStream b64os = new Base64OutputStream(baos, true, 0, null);
		encrypt(keyLength, password, is, b64os);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return new String(baos.toByteArray(), "UTF-8");
	}


	public static String decrypt(char[] password, String input)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		//		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(getBytes(input.toCharArray())), false);
		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(input.getBytes("UTF-8")), false);

		BufferedInputStream is = new BufferedInputStream(b64os);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		decrypt(password, is, baos);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return new String(baos.toByteArray(), "UTF-8");
	}


	public static String encryptB32(int keyLength, char[] password, String input)
			throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException {
		//BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(getBytes(input.toCharArray())));
		BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(input.getBytes("UTF-8")));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Base32OutputStream b32os = new Base32OutputStream(baos, true, 0, null);
		encrypt(keyLength, password, is, b32os);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return new String(baos.toByteArray(), "UTF-8");
	}


	public static String decryptB32(char[] password, String input)
			throws InvalidPasswordException, InvalidAESStreamException, IOException, StrongEncryptionNotAvailableException {
		//		Base64InputStream b64os = new Base64InputStream(new ByteArrayInputStream(getBytes(input.toCharArray())), false);
		Base32InputStream b32os = new Base32InputStream(new ByteArrayInputStream(input.getBytes("UTF-8")), false);

		BufferedInputStream is = new BufferedInputStream(b32os);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		decrypt(password, is, baos);
		baos.flush();
		//		return String.valueOf(getChars(baos.toByteArray()));
		return new String(baos.toByteArray(), "UTF-8");
	}

	/**
	 * A tuple of encryption and authentication keys returned by {@link #keygen}
	 */
	private final static class Keys {
		public final SecretKey encryption, authentication;


		public Keys(SecretKey encryption, SecretKey authentication) {
			this.encryption = encryption;
			this.authentication = authentication;
		}
	}

	//******** EXCEPTIONS thrown by encrypt and decrypt ********

	/**
	 * Thrown if an attempt is made to decrypt a stream with an incorrect
	 * password.
	 */
	public static class InvalidPasswordException extends Exception {
		private static final long serialVersionUID = -9199105385887970429L;
	}

	/**
	 * Thrown if an attempt is made to encrypt a stream with an invalid AES key
	 * length.
	 */
	public static class InvalidKeyLengthException extends Exception {
		private static final long serialVersionUID = -7469609265016273051L;


		InvalidKeyLengthException(int length) {
			super("Invalid AES key length: " + length);
		}
	}

	/**
	 * Thrown if 192- or 256-bit AES encryption or decryption is attempted,
	 * but not available on the particular Java platform.
	 */
	public static class StrongEncryptionNotAvailableException extends Exception {
		private static final long serialVersionUID = -6817500448962450693L;


		public StrongEncryptionNotAvailableException(int keySize) {
			super(keySize + "-bit AES encryption is not available on this Java platform.");
		}
	}

	/**
	 * Thrown if an attempt is made to decrypt an invalid AES stream.
	 */
	public static class InvalidAESStreamException extends Exception {
		private static final long serialVersionUID = -3489875493550420447L;


		public InvalidAESStreamException() {
			super();
		};


		public InvalidAESStreamException(Exception e) {
			super(e);
		}
	}

}