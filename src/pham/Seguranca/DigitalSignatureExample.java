package pham.Seguranca;
/**
 * Objetivo do trabalho:
 * 
 * Construir um programa Java utilizando a JCA que recebe um texto na linha de comando e assina
 * o mesmo. O processo de geração da assinatura e verificação da mesma deve ser feito sem a
 * utilização da classe Signature, detalhando-se na saída padrão cada um dos passos
 * executados, inclusive apresentando o digest e a assinatura no formato hexadecimal.
 * 
 * 
 * Grupo N:
 * 
 * Gabriel Lima #0921598
 * Luiz Henrique T. Cobucci #0812344
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;

// este exemplo utililiza facilidades para a geracao e verificacao
// de assinatura digital
public class DigitalSignatureExample {

	public static void main(String[] args) throws Exception {

		// verifica args e recebe o texto plano
		if (args.length != 1) {
			System.err.println("Usage: java DigitalSignatureExample text");
			System.exit(1);
		}
		byte[] plainText = args[0].getBytes("UTF8");

		// gera o par de chaves RSA
		System.out.println("\nStart generating RSA key");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair key = keyGen.generateKeyPair();
		System.out.println("Finish generating RSA key");

		// define um objeto signature para utilizar MD5 e RSA
		// e assina o texto plano com a chave privada,
		// o provider utilizado tambem eh impresso
		MySignature sig = MySignature.getInstance("MD5WithRSA");
		sig.initSign(key.getPrivate());
		sig.update(plainText);
		byte[] signature = sig.sign();
		// System.out.println(sig.getProvider().getInfo());
		System.out.println("\nSignature:");

		// converte o signature para hexadecimal
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < signature.length; i++) {
			String hex = Integer.toHexString(0x0100 + (signature[i] & 0x00FF))
					.substring(1);
			buf.append((hex.length() < 2 ? "0" : "") + hex);
		}

		// imprime o signature em hexadecimal
		System.out.println(buf.toString());

		// verifica a assinatura com a chave publica
		System.out.println("\nStart signature verification");
		sig.initVerify(key.getPublic());
		sig.update(plainText);
		if (sig.verify(signature)) {
			System.out.println("Signature verified");
		} else
			System.out.println("Signature failed");
	}
}
