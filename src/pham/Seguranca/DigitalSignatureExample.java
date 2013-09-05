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
 * Grupo 2:
 * 
 * Anderson Moreira #
 * Paulo Henrique C. Alves #0911325
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Scanner;

// este exemplo utililiza facilidades para a geracao e verificacao
// de assinatura digital
public class DigitalSignatureExample {

	public static void main(String[] args) throws Exception {

		/* Usar na linha de comando */
		// verifica args e recebe o texto plano
		/*if (args.length != 1) {
			System.err.println("Usage: java DigitalSignatureExample text");
			System.exit(1);
		}
		byte[] plainText = args[0].getBytes("UTF8");
		*/
		/* FIM - Usar na linha de comando */
		
		/* Usar no eclipse */
		Scanner reader = new Scanner(System.in);  
        String text;
        System.out.println ("Insert a string");
        text = reader.next();
        reader.close();
        byte[] plainText = text.getBytes("UTF8");
        /* FIM - Usar no eclipse */

		// gera o par de chaves RSA
		System.out.println("\nStart generating RSA key");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair key = keyGen.generateKeyPair();
		System.out.println("Finish generating RSA key");

		// define um objeto signature para utilizar MD5 e RSA
		// e assina o texto plano com a chave privada
		MySignature sig = MySignature.getInstance("MD5WithRSA");
		sig.initSign(key.getPrivate());
		sig.update(plainText);
		byte[] signature = sig.sign();
		
		System.out.println("\nSignature:");
		sig.printHexa(signature);

		// verifica a assinatura com a chave publica
		System.out.println("\nStart signature verification");
		sig.initVerify(key.getPublic());
		sig.update(plainText);
		if (sig.verify(signature)) {
			System.out.println("\nSignature verified");
		} else
			System.out.println("\nSignature failed");
	}
}
