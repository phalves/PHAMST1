package pham.Seguranca;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class MySignature {
	
	/* class variables */
	
	private MessageDigest messageDigest;
	private Cipher cipher;
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	private byte[] message;
	
	
	/* class methods */
	
	public static MySignature getInstance(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
		
		// Split the algorithm names that are going to be used
		StringTokenizer stringTokenizer = new StringTokenizer(algorithm);
		String hashAlgorithm = stringTokenizer.nextToken("With");
		String cipherAlgorithm = stringTokenizer.nextToken("With");
		
		MySignature mySignature = new MySignature();
						
		mySignature.messageDigest = MessageDigest.getInstance(hashAlgorithm);
		mySignature.cipher = Cipher.getInstance(cipherAlgorithm);					
		
		return mySignature;
	}
	
	public void initSign(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public void update(byte[] data) throws SignatureException {
		this.message = data;
	}
	
	public byte[] sign() throws SignatureException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		messageDigest.update(message);
		byte[] digestedMessage = messageDigest.digest();
		
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] signedMessage = cipher.doFinal(digestedMessage);
		
		return signedMessage;
	}
	
	public void initVerify(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	public boolean verify(byte[] signature) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] newDigest = cipher.doFinal(signature);
		
		messageDigest.update(message);
		byte[] originalDigest = messageDigest.digest();
		
		for (int i = 0; i < newDigest.length; i++) {
			if (newDigest[i] != originalDigest[i])
				return false;
		}
		
		return true;
	}
}