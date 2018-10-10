/* Author  : Aaron Parks
 * Course  : CSS 527 Cryptology and Data Assurance
 * Quarter : Autumn 2014
 * Assign- : Final Project
 *
 * Description:
 * Provides a suvery of three differnt cryptography libraries for Java.  The three libraries tested are
 * are as follows:
 *   <> SunJCE -> default Java encryption library
 *   <> Bouncy Castle -> probably the second most popular Java encryption library (there is a lot of
 *                       information online on how to use it)
 *   <> FlexiCore -> a third library that probably works, but doesn't integrate into the existing SunJCE
 *                   code as Bouncy Castle
 * Program executes within three nested for loops which iterate through a string array of providers,
 * encryption schema, and number of trials.  Five trials are recorded for each provider and encryption schema
 * to obtain an average execution time for each instance.
 */
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import de.flexiprovider.core.FlexiCoreProvider;

public class Numbers {

	public static void main(String[] args) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new FlexiCoreProvider());	
		
		//file to be manipulated
		Path filePath = Paths.get("blackfriday.mp3");
		byte[] data = Files.readAllBytes(filePath);
		
		//for trial time collection and mathematics at the end of the trials
		long[] trials = new long[5];
		long startTime = 0;
		long endTime   = 0;
		long programStart = 0;
		
		String[] providers = new String[] {"JCE","BC","FlexiCore"};
		String[] symmetric = new String[] {"AES/CBC/PKCS5Padding","DES/CBC/PKCS5Padding","Blowfish/CBC/PKCS5Padding"};
		String[] stream = new String[] {"AES/CFB8/NoPadding","DES/CFB8/NoPadding","RC4"};
		//String[] asymmetric = new String[] {"RSA","DSA","ECIES"};  <-- couldn't get al these working before assignment due
		String[] asymmetric = new String[] {"RSA"};
		String[] hashModes = new String[] {"MD5","SHA1","SHA512"};
		
		//for testing hash output  //hash output won't display for final output
		String hash = "\0";
		
		programStart = System.currentTimeMillis();
		for (int provider_iterator = 0; provider_iterator < providers.length; provider_iterator++) {
			drawScreen(providers[provider_iterator]);
			
			//need to skip symmetric and asymmetric encryption for FlexiCore
			//  it's stubborn as a mule to get working correctly!
			if (!providers[provider_iterator].equals("FlexiCore")) {
				//FIRST TEST
				System.out.println("SYMMETRIC KEY");
				for (int symmetric_iterator = 0; symmetric_iterator < symmetric.length; symmetric_iterator++) {
					for (int si_inLoop = 0; si_inLoop < trials.length; si_inLoop++) {
						try {
							startTime = System.currentTimeMillis();
							symmetricEncryptDecrypt(data, getEncryptionKey(symmetric[symmetric_iterator].split("/")[0]), symmetric[symmetric_iterator], providers[provider_iterator]);
						}
						catch (IllegalBlockSizeException
								| BadPaddingException
								| NoSuchAlgorithmException
								| NoSuchProviderException e) {
							e.printStackTrace();
						}
						endTime = System.currentTimeMillis();
						trials[si_inLoop] = (endTime - startTime);
					}
					//display test summary
					System.out.println("   Cipher   : " + symmetric[symmetric_iterator]);
					System.out.println("   Avg Time : " + getAverage(trials) + " ms");
					//reset array
					Arrays.fill(trials, 0);
				} //END FIRST TEST */
			
				//SECOND TEST
				System.out.println("STREAM CIPHERS");
				for (int stream_iterator = 0; stream_iterator < stream.length; stream_iterator++) {
					for (int si_inLoop = 0; si_inLoop < trials.length; si_inLoop++) {
						try {
							startTime = System.currentTimeMillis();
							symmetricEncryptDecrypt(data, getEncryptionKey(stream[stream_iterator].split("/")[0]), stream[stream_iterator], providers[provider_iterator]);
						}
						catch (IllegalBlockSizeException
								| BadPaddingException
								| NoSuchAlgorithmException
								| NoSuchProviderException e) {
							e.printStackTrace();
						}
						endTime = System.currentTimeMillis();
						trials[si_inLoop] = (endTime - startTime);
					}
					//display test summary
					System.out.println("   Cipher   : " + stream[stream_iterator]);
					System.out.println("   Avg Time : " + getAverage(trials) + " ms");
					//reset array
					Arrays.fill(trials, 0);
				} //END SECOND TEST
			} //END FLEXICORE IF STATEMENT
		
			//THIRD TEST
			System.out.println("ASYMMETRIC KEY");
			for (int asymmetric_iterator = 0; asymmetric_iterator < asymmetric.length; asymmetric_iterator++) {
				for (int ai_inLoop = 0; ai_inLoop < trials.length; ai_inLoop++) {
					try {
						startTime = System.currentTimeMillis();
						System.out.println(" Trial #" + ai_inLoop);  //<-- included to provide signal to user that program hasn't stalled or crashed
						RSAEncryptDecrypt(data, asymmetric[asymmetric_iterator], providers[provider_iterator]);
						endTime = System.currentTimeMillis();
					}
					catch (InvalidKeyException
							| NoSuchAlgorithmException
							| InvalidAlgorithmParameterException
							| NoSuchProviderException e) {
						e.printStackTrace();
					}
					endTime = System.currentTimeMillis();
					trials[ai_inLoop] = (endTime - startTime);
				} 
				System.out.println("   Cipher     : " + asymmetric[asymmetric_iterator]);
				System.out.println("   Avg Time   : " + (double)getAverage(trials)/60000 + " minutes");
				//reset array
				Arrays.fill(trials,0);
			} //END THIRD TEST
			
			//FOURTH TEST
			System.out.println("HASHING");
			for (int hash_iterator = 0; hash_iterator < hashModes.length; hash_iterator++) {
				for (int hi_inLoop = 0; hi_inLoop < trials.length; hi_inLoop++) {
					startTime = System.currentTimeMillis();
					try {
						hash = hashFile(data, hashModes[hash_iterator], providers[provider_iterator]);
					}
					catch (NoSuchAlgorithmException | NoSuchProviderException e) {
						e.printStackTrace();
					}
					endTime = System.currentTimeMillis();
					trials[hi_inLoop] = (endTime - startTime);
				}
				System.out.println("   Mode: " + hashModes[hash_iterator]);
				System.out.println("   Avg Time: " + getAverage(trials) + " ms");
				//reset array
				Arrays.fill(trials, 0);
			} //END FOURTH TEST
		} //END 'PROVIDER' LOOP
		System.out.println("\nTotal Execution Time: " + (double)(System.currentTimeMillis() - programStart)/60000 + " minutes");
	} //END 'MAIN'
	
	// method "RSAEncryptDecrypt()"
	/* Performs RSA encryption and decryption on a file.  Encryption is done with the public key
	 * while decryption is done with the private key.  Beacuse of the size of the file and the 
	 * built-in restrictions of Java, the prameter file had to be broken into 245-byte pieces and
	 * encrypted / decrypted separately.  The size of each piece is based upon the the key size. */
	public static void RSAEncryptDecrypt(byte[] param, String instance, String provider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
		byte[] cipherData = null;
		KeyPairGenerator kpgObject = null;
		
		//used for breaking parameter into manageable pieces for encryption / decryption
		byte[] chunk = new byte[245];
		int startIndex = 0;
		int endIndex = chunk.length-1;
		final int OFFSET = chunk.length;
		Cipher thisCipher = null;
		
		if (!provider.equals("JCE"))
			kpgObject = KeyPairGenerator.getInstance(instance, provider);
		else
			kpgObject = KeyPairGenerator.getInstance(instance);

		kpgObject.initialize(2048);
		KeyPair kPair = kpgObject.generateKeyPair();
		
		//encryption and decryption
		try {
			if (!provider.equals("JCE"))
				thisCipher = Cipher.getInstance(instance, provider);
			else
				thisCipher = Cipher.getInstance(instance);
			for (int i = 0; i < Math.ceil((double)param.length/chunk.length); i++) {
				if (i % 10000 == 0) //<-- for status updates so user doesn't think program crashed / froze
					System.out.println("Chunk # " + i);
				chunk = Arrays.copyOfRange(param, startIndex, endIndex);
				thisCipher.init(Cipher.ENCRYPT_MODE, kPair.getPublic());
				cipherData = thisCipher.doFinal(chunk);
				thisCipher.init(Cipher.DECRYPT_MODE, kPair.getPrivate());
				thisCipher.doFinal(cipherData);
				//clear array
				Arrays.fill(chunk,(byte)0);
				
				//adjust indices
				startIndex = endIndex + 1;
				endIndex += OFFSET;
				//adjust the endIndex pointer to point at last element if out of bounds
				if (endIndex >= param.length)
					endIndex = param.length - 1;
				//safety net to prevent OutOfBounds error
				if (startIndex >= param.length)
					break;
			}
		}
		catch (Exception e) {
			System.out.println("Encryption / Decryption error: " + e.toString());
		}
	}
	
	public static void symmetricEncryptDecrypt(byte[] param, byte[] key, String instance, String provider) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
		String cipher = instance.split("/")[0];
		byte[] encrypted = null;
		byte[] IV = getInitializationVector(cipher);		
		Cipher thisCipher = null;
		SecretKeySpec secretKey = new SecretKeySpec(key, cipher);
		IvParameterSpec secretIV = new IvParameterSpec(IV);
		
		try {

			if (!provider.equals("JCE"))
				thisCipher = Cipher.getInstance(instance, provider);
			else
				thisCipher = Cipher.getInstance(instance);

			if (instance.equals("RC4"))
				thisCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			else
				thisCipher.init(Cipher.ENCRYPT_MODE, secretKey, secretIV);
				
			encrypted = thisCipher.doFinal(param);
		}
		catch (Exception e) {
			System.out.println("Encryption error: " + e.toString());
		}
		//decryption
		try {
			if (instance.equals("RC4"))
				thisCipher.init(Cipher.DECRYPT_MODE, secretKey);
			else
				thisCipher.init(Cipher.DECRYPT_MODE, secretKey, secretIV);
				
			thisCipher.doFinal(encrypted);
		}
		catch (Exception e) {
			System.out.println("Decryption error: " + e.toString());
		}
	}
	//method "hashFile()"
	/* Hashes the parameter byte array.  The type of hash is based upon the 'instance' and
	 * 'provider' in the parameter.  Can be made to return a string result if necessary.
	 * Known working instances are: MD5, SHA-1, and SHA-256
	 * Known working providers are: JCE (default), BC */
	private static String hashFile(byte[] param, String instance, String provider) throws NoSuchAlgorithmException, NoSuchProviderException{
		MessageDigest md;
		if (!provider.equals("JCE"))
			md = MessageDigest.getInstance(instance, provider);
		else
			md = MessageDigest.getInstance(instance);
		md.update(param);
		byte[] digestBytes = md.digest();
			
		//convert byte array to hex
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < digestBytes.length; i++)
			sb.append(Integer.toString((digestBytes[i] & 0xff) + 0x100, 16).substring(1));
		return sb.toString();
	}

	// method "getEncryptionKey()"
	/* Returns an appropriately sized encryption key either a symmetric or stream cipher.  The
	 * cipher types supported include AES, DES, Blowfish, and RC4.  Function will always return
	 * the hard-coded encryption key unless the calling cipher is DES (independent of the mode). */
	private static byte[] getEncryptionKey(String cipherType) {
		byte[] desKey = null;
		byte[] encryptionKey = new byte[] {85, -108, 4, -42, 8, -23, 15, -16, 16, -15, 23, -8, 42, -4, 108, 85};
		if (cipherType.equals("DES")) {
			//DES requires an 8-byte (64-bit) encryption key
			desKey = new byte[8];
			for (int i = 0; i < desKey.length; i++)
				desKey[i] = encryptionKey[i];
			return desKey;
		}
		//if not DES will just return the byte array with 16 bytes
		return encryptionKey;
	}
	//method "getInitializationVector()"
	/* 'Selector' for IVs to satisfy the different IV constraints by different 
	 * symmetric ciphers.  Only designed to support AES, DES, and Blowfish by
	 * default. */
	private static byte[] getInitializationVector(String cipherType) {
		byte[] notAESIV = null;
		byte[] IV = new byte[] {11, -37, 13, -31, 17, -29, 19, -23, 23, -19, 29, -17, 31, -13, 37, -11};
		if (cipherType.equals("DES") || cipherType.equals("Blowfish")) {
			//DES and Blowfish require an 8-byte (64-bit) IV
			notAESIV = new byte[8];
			for (int i = 0; i < notAESIV.length; i++)
				notAESIV[i] = IV[i];
			return notAESIV;
		}
		//if AES will just return the byte array with 16 bytes
		return IV;
	}
	// method "getAverage()"
	/* Calculates the average of the values stored in the parameter array.  Casts the resulting
	 * value to a double. */
	private static double getAverage(long[] param) {
		long holder = 0;
		for (int i = 0; i < param.length; i++)
			holder += param[i];
		return (double)holder/param.length;
	}
	// method "drawScreen()"
	/* Draws a "title card" to the console.  Uses a hash map to map the string parameter
	 * to the title string. */
	private static void drawScreen(String provider) {
		Map<String, String> vars = new HashMap<String, String>();
		vars.put("JCE","| PROVIDER: \"SunJCE\" |");
		vars.put("BC","| PROVIDER: \"Bouncy Castle\" |");
		vars.put("FlexiCore","| PROVIDER: \"FlexiCore Provider\" |");
		
		for (int i = 0; i < 3; i++ ) {
			if (i % 2 == 0) {
				for (int j = 0; j < vars.get(provider).length(); j++)
					System.out.print("=");
				System.out.println();	
			}
			if (i == 1)
				System.out.println(vars.get(provider));
		}	
	}
}