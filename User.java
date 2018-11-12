import java.io.*;
import java.net.Socket;
import java.util.Scanner;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;
import java.nio.charset.Charset;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.ObjectInputStream;


public class User{
	
	public static void main(String[] args){
		/**Server's IP Address**/
		String ipAddress;

		/**Port number for communication**/
		int portNumber;

		/**Scanner for user input**/
		Scanner scn = new Scanner(System.in);

		/**Socket to connect to Server**/
		Socket socket = null;

		/**For sending information to Server**/
		PrintWriter out = null;

		/**For receiving information from the Server**/
		BufferedReader in = null;

		/**For receiving information from Standard Input
		 * (Probably could just use the Scanner) **/
		BufferedReader stdIn = null;

		/**Holds the most recent user input**/
		String userInput;

		try{
			//Hard Coded Server's Ip and Port Number
			ipAddress = "127.0.0.1";
			portNumber = 9876;
			
			//Attempting to connect to Server
			socket = new Socket(ipAddress, portNumber);
			out = new PrintWriter(socket.getOutputStream(),true);
			in = new BufferedReader(new InputStreamReader(
						socket.getInputStream()));
			stdIn = new BufferedReader(
					new InputStreamReader(System.in));

			//Receiving RSA public key from the server
			PublicKey publicKey = null;
			ObjectInputStream rsaKeyStream = new ObjectInputStream(socket.getInputStream());
			try{
				publicKey = (PublicKey) rsaKeyStream.readObject();
			}catch(Exception ex){
			}
			System.out.println("Received Public key: " + publicKey); 
			
		

			//Creating random AES key
			String AESkey = generateRandomAESkey();
			System.out.println("Generated AES key: " + AESkey);

			//Encrypting AES key
			try{
				byte[] temp  = RSA.encrypt(publicKey, AESkey);
				System.out.println("Size of temp: " + temp.length);
				String encryptedAESkey = new String(temp);
				System.out.println("Encrypted AES using RSA public key from server: " + encryptedAESkey);

				//Sending encrypted AES key
			       //	out.println(encryptedAESkey);
			       DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
			       dOut.writeInt(temp.length);
			       dOut.write(temp);
			}catch(Exception ex){
				System.err.println("Error with Encrypting AES key: " + ex);
				System.exit(1);
			}

			

		//	out.println(AESkey);
			String encrpytedString = in.readLine();
			System.out.println("Received Encrpyted String: " + encrpytedString);
			String decryptedString = AES.decrypt(encrpytedString, AESkey);
			System.out.println("Decrypted String: " + decryptedString);

			System.out.println(in.readLine());
			out.println(stdIn.readLine());

			new inputThread(socket, AESkey).start();
			
			while((userInput = stdIn.readLine()) != null){
				out.println(AES.encrypt(userInput, AESkey));


				if(userInput.equals("Exit")){
					System.exit(0);
					break;
				}

			}

			System.out.println("You have disconnected");


		}catch(IOException e){
			System.err.println("ERROR");
			System.exit(1);
		}
	}

	public static String generateRandomAESkey(){
		byte[] temp = new byte[10]; //10 char
		new Random().nextBytes(temp);
		
		return new String(temp, Charset.forName("UTF-8"));
	}


}

class inputThread extends Thread{
	Socket socket;
	String AESkey;

	inputThread(Socket socket, String AESkey){
		this.socket = socket;
		this.AESkey = AESkey;
	}

	@Override
	public void run(){
		try{
			BufferedReader in = new BufferedReader(
					new InputStreamReader(socket.getInputStream()));
			String inputLine;

			while((inputLine = in.readLine()) != null){
				inputLine = AES.decrypt(inputLine, AESkey);
				if(inputLine.equals("Exit")){
					//You have been kicked
					System.exit(0);
				}
				System.out.println(inputLine);
			}

		}catch(IOException e){
			System.err.println("Error receiving message from server");
			System.exit(1);
		}	
	}
}
//Source: https://howtodoinjava.com/security/java-aes-encryption-example/
class AES {
 
    private static SecretKeySpec secretKey;
    private static byte[] key;
 
    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
 
    public static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
 
    public static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}

class RSA {
	
	public static KeyPair buildKeyPair() throws NoSuchAlgorithmException{
		final int keySize = 2048;
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keySize);
		return keyPairGenerator.genKeyPair();
	}

	public static byte[] encrypt(PublicKey publicKey, String message) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(message.getBytes());
	}

	public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(encrypted);
	}
}
