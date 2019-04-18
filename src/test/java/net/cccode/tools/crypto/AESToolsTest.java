package net.cccode.tools.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import net.cccode.tools.crypto.AESTools.InvalidAESStreamException;
import net.cccode.tools.crypto.AESTools.InvalidKeyLengthException;
import net.cccode.tools.crypto.AESTools.InvalidPasswordException;
import net.cccode.tools.crypto.AESTools.StrongEncryptionNotAvailableException;

public class AESToolsTest {

	private static final Log logger = LogFactory.getLog(AESToolsTest.class);


	@Test
	public void testFileEncrypt() {
		char[] password = null;
		try (InputStream file = AESTools.class.getResourceAsStream("original.txt")) {
			password = Base64.encodeBase64String(AESTools.SHA1Digest(file)).toCharArray();
		} catch (IOException e) {
			logger.warn(e, e);
		}
		Assert.assertNotNull("password should not be null ", password);
		logger.info(String.valueOf(password));

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(AESTools.class.getResourceAsStream("original.txt")))) {
			String tempString = null;

			while ((tempString = reader.readLine()) != null) {
				if (StringUtils.trimToEmpty(tempString).toUpperCase().equals("#AES")) {
					System.out.println("line:" + tempString);
					AESTools.encrypt(128, password, AESTools.class.getResourceAsStream("original.txt"),
							new Base64OutputStream(new FileOutputStream(new File("d:/enc.txt")), true, 0, null));

					AESTools.decrypt(password, new Base64InputStream(new FileInputStream(new File("d:/enc.txt")), false, 0, null),
							new FileOutputStream(new File("d:/dec.txt")));
					break;
				}
			}
		} catch (IOException | InvalidKeyLengthException | StrongEncryptionNotAvailableException | InvalidPasswordException
				| InvalidAESStreamException e) {
			logger.warn(e, e);
		}

	}


	/**
	 * 字符串加密解密
	 * 
	 * @throws InvalidKeyLengthException
	 * @throws StrongEncryptionNotAvailableException
	 * @throws IOException
	 * @throws InvalidPasswordException
	 * @throws InvalidAESStreamException
	 */
	@Test
	public void testStringEncrypt() throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException,
			InvalidPasswordException, InvalidAESStreamException {
		char[] password = "密码".toCharArray();

		final String original = "AES加密解密";
		System.out.println(original);
		String encrypted = AESTools.encrypt(128, password, original);
		System.out.println(encrypted);

		String decrypted = AESTools.decrypt(password, encrypted);
		System.out.println(decrypted);
		Assert.assertEquals("strings should be equal", original, decrypted);

		byte[] originalArr = "AES加密解密".getBytes("UTF-8");
		System.out.println(new String(originalArr, "UTF-8"));
		byte[] encryptedArr = AESTools.encrypt(128, password, originalArr);
		System.out.println(Base64.encodeBase64String(encryptedArr));

		byte[] decryptedArr = AESTools.decrypt(password, encryptedArr);
		System.out.println(new String(decryptedArr, "UTF-8"));
		Assert.assertArrayEquals("arrays should be equal", originalArr, decryptedArr);
	}


	/**
	 * 测试密文随机性
	 * 
	 * @throws InvalidKeyLengthException
	 * @throws StrongEncryptionNotAvailableException
	 * @throws IOException
	 * @throws InvalidPasswordException
	 * @throws InvalidAESStreamException
	 */
	@Test
	public void testRandomness() throws InvalidKeyLengthException, StrongEncryptionNotAvailableException, IOException,
			InvalidPasswordException, InvalidAESStreamException {
		char[] password = "testRandomness_password".toCharArray();
		final String original = "testRandomness";
		System.out.println(original);

		String encrypted1 = AESTools.encrypt(256, password, original);
		String encrypted2 = AESTools.encrypt(256, password, original);
		System.out.println(encrypted1);
		System.out.println(encrypted2);
		Assert.assertNotEquals("strings should not be equal", encrypted1, encrypted2);
		String decrypted1 = AESTools.decrypt(password, encrypted1);
		String decrypted2 = AESTools.decrypt(password, encrypted2);
		System.out.println(decrypted1);
		System.out.println(decrypted2);
		Assert.assertEquals("strings should be equal", decrypted1, decrypted2);

	}
}
