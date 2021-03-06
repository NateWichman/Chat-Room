
import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.Vector;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
 
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/****************************************************
 	Runs a basic chat room server. Allows for 
multiple users to connect at once. Allows users to
either send messages to all other users or to just 
specific users. Allows administors to kick specific
users if they enter a password.

@author Nathan Wichman
@version Fall 2018
****************************************************/

public class Server{
	public static Vector<Client> clients = new Vector<Client>();
	public static String adminPassword = "123";

	public static void main(String args[]){
		/**to hold all connected clients**/
	//	Vector<Client> clients = new Vector<Client>();

		/**Socket for the Server**/
		ServerSocket serverSocket = null;

		/**Port number for socket connection**/
		int portNumber;

		//Setting port number
		portNumber = 9876;

		/** RSA key material **/
		KeyPair keyPair = null;
		PrivateKey privateKey = null;
		PublicKey publicKey = null;

		try{
			//Creating key pairs, see class RSA for more information
			keyPair = RSA.buildKeyPair();
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
		}catch(NoSuchAlgorithmException e){
			System.err.println("ERROR creating RSA keys");
			System.exit(1);
		}catch(Exception e2){
		}

		
		//Attaching the Server Socket to the port number
		try{
			serverSocket = new ServerSocket(portNumber);
		}catch(IOException e){
			System.err.println("Error in creating Server Socket at port " + portNumber);
			System.exit(1);
		}

		while(true){
			//Socket for the client
			Socket clientSocket = null;

			System.out.println("Waiting for client connection...");

			try{
				//Pauses until client joins the socket
				clientSocket = serverSocket.accept();
			}catch(IOException e){
				System.err.println("ERROR accepting client connection");
				System.exit(1);
			}
			/*Starting a new client thread to manage this 
			client, so we can wait for a new client in this loop */
			new ClientThread(clientSocket, publicKey, privateKey).start();
		}
	}
}

class ClientThread extends Thread{
	private Client client;
	private Socket clientSocket;
	private PrintWriter out;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	BufferedReader in;

	ClientThread(Socket clientSocket, PublicKey publicKey, PrivateKey privateKey){
		this.clientSocket = clientSocket;
		this.publicKey = publicKey;
		this.privateKey = privateKey;

		try{
			//For sending information
			out = new PrintWriter(clientSocket.getOutputStream(),true);
			//for receiving information
			in = new BufferedReader(
					new InputStreamReader(clientSocket.getInputStream()));
		}catch(IOException e){
			System.err.println("Error creating new client");
		}
	}

	@Override
	public void run(){
		try{	
			//For sending an object instead of text, in this case the RSA public key
			ObjectOutputStream rsaOutputStream =
				new ObjectOutputStream(clientSocket.getOutputStream());

			//Sending RSA public key
			System.out.println("\nSending RSA public key: " + publicKey);
			rsaOutputStream.writeObject(publicKey);

			//Receiving Encrypted AES key from client
			DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
			int length = dIn.readInt();
			byte[] encryptedAESkey = null;
			if(length > 0){
				encryptedAESkey = new byte[length];
				dIn.readFully(encryptedAESkey, 0, encryptedAESkey.length);
			}

			
			//Decrypting AES key with RSA private key
			String AESkey = null;
			try{
				System.out.println("\nEncryped AES key recived from client: " + new String(encryptedAESkey));
				byte[] temp = RSA.decrypt(privateKey, encryptedAESkey);
				AESkey = new String(temp);
			}catch(Exception ex){
				System.err.println("\nError Decrypting AES key: " + ex);
			}

			System.out.println("\nDecrypted AESkey: " + AESkey);
			
			//Sending a tester string to make sure decryption and encryption on both ends works
			String originalString = "Hola Mundo!";
			String encrpytedString = AES.encrypt(originalString, AESkey);
			System.out.println("\nEncrypting: " + originalString + "\nto: " + encrpytedString);
			out.println(encrpytedString);

			//Getting username
			out.println(AES.encrypt("Enter a UserName: ", AESkey));
			String userName = in.readLine(); 
			System.out.println(userName + " has joined");
			out.println(AES.encrypt("\n\nWelcome to the Server!", AESkey));
			out.println(AES.encrypt("Type any message and hit ENTER to send to all users", AESkey));
			out.println(AES.encrypt("/list: Displays a list of all connected users", AESkey));
			out.println(AES.encrypt("/whisper username: Sends a message only to the selected user", AESkey));
			out.println(AES.encrypt("/kick username: Kicks a user (requires admin password)", AESkey));
			out.println(AES.encrypt("\n\n", AESkey));

			//Creating a client object, also adds client to static clients vector in this class (in constructor)
			 client = new Client(clientSocket, userName, AESkey);

		 	//To hold messages sent from this particular client
			String receivedMessage;

			//Receiving messages from the Client
			while((receivedMessage = in.readLine()) != null){
				System.out.println("Encrypted Message Received: " + receivedMessage);

				//Decrypting message with AES key
				receivedMessage = AES.decrypt(receivedMessage, AESkey);
				System.out.println("Decrypted to: " + receivedMessage);

				/*Reseting printwriter to connect to this threads client just in case it was replaced in
				a different method. */
				out = new PrintWriter(client.getSocket().getOutputStream(), true);
				System.out.println(client.getUserName() + ": " + receivedMessage);
				
				if(receivedMessage.equals("Exit")){
					System.out.println(client.getUserName() + " has dissconnected");
					break;
				}else if(receivedMessage.startsWith("/whisper")){
					System.out.println(userName + " is trying to whisper");
					whisperMessage(receivedMessage);
				}else if(receivedMessage.startsWith("/list")){
					sendClientList(client);
				}else if(receivedMessage.startsWith("/kick")){
					kickUser(receivedMessage);
				}else{
					broadcastMessage(client.getUserName() + ": " + receivedMessage);
				}
			}
		
			Server.clients.removeElement(client);
			broadcastMessage("\n" + client.getUserName() + " has disconnected");
			
		}catch(IOException e){
			System.err.println("ERROR handling client in method run: " + e);
		}

	}
	/****************************************************
	 This method kicks a user of the chat by parsing the
	message parameter.

	@Param message of the format "/kick username "
	 * ***********************************************/
	private void kickUser(String message){
		try{
			//Setting the printwriter to the client who sent the kick request
			out = new PrintWriter(client.getSocket().getOutputStream(), true);
			BufferedReader tempIn = new BufferedReader(
					new InputStreamReader(client.getSocket().getInputStream()));
			String userName = "";
			try{
				int userNameStart = message.indexOf(" ");
				int userNameEnd = message.indexOf(" ", userNameStart + 1);
				userName = message.substring(userNameStart + 1, userNameEnd);
			}catch(IndexOutOfBoundsException e){
				out.println(AES.encrypt("Incorrect kick format, use /kick username", client.getAESkey()));
				return;
			}
			System.out.println("Recieved Correct kick command");
			String input;
			out.println(AES.encrypt("\nEnter Admin Password: ", client.getAESkey()));

			//Receiving attempted Admin password
			input = AES.decrypt(tempIn.readLine(), client.getAESkey());
			if(input.equals(Server.adminPassword)){
				System.out.println("Correct Admin Password");
			}else{
				out.println(AES.encrypt("\nPASSWORD WAS NOT CORRECT", client.getAESkey()));
			}
			boolean clientKicked = false;

			//Searching through the client vector to see if one by that name exists, if so removing them
			for(Client c : Server.clients){
				if(c.getUserName().equals(userName)){
					PrintWriter tempOut = new PrintWriter(c.getSocket().getOutputStream(), true);
					tempOut.println(AES.encrypt("\nYou have been kicked from the server by an admin", c.getAESkey()));
					tempOut.println(AES.encrypt("Exit", c.getAESkey()));
					Server.clients.removeElement(c);
					clientKicked = true;
					broadcastMessage(userName + " has been kicked from the server");
				}
			}
			if(!clientKicked){
				out.println(AES.encrypt("No User found by that name to kick from server", client.getAESkey()));
			}
		}catch(IOException e3){
			System.err.println("Error in method: kickUser");
		}
	}
	/****************************************************
	 *Sends a message to just one particular user instead
	 of broadcasting it to all users

	 @param message of the format "/whisper username message"
	 * ************************************************/
	private void whisperMessage(String message){
		try{
			int userNameStart = message.indexOf(" ");
			int userNameEnd = message.indexOf(" ", userNameStart + 1);
			String userName = message.substring(userNameStart + 1, userNameEnd);
			System.out.println("A message is being whipered to " + userName);

			boolean ClientFound = false;
			
			//Searching for the requested user to whisper to
			for(Client c : Server.clients){
				if(c.getUserName().equals(userName)){
					ClientFound = true;
					try{
						String cutMessage = message.substring(userNameEnd);
						out = new PrintWriter(c.getSocket().getOutputStream(),true);
						out.println(AES.encrypt(("\n" + client.getUserName() + " is whispering to you: " + cutMessage), c.getAESkey()));
					}catch(IOException e3){
						System.err.println("Error forwarding whisper");
					}
				}
			} 

			if(!ClientFound){
				try{
					out = new PrintWriter(client.getSocket().getOutputStream(), true);
					out.println(AES.encrypt(("\nNo user found by the username: " + userName), client.getAESkey()));
				}catch(IOException e4){
					System.err.println("Error sending no user found for whisper functionality");
				}
			}
			
		}catch(IndexOutOfBoundsException e){
			System.err.println("No Message Attached to Whisper");
			try{
				out = new PrintWriter(client.getSocket().getOutputStream(),true);
				out.println(AES.encrypt("No Message Attached to Whisper", client.getAESkey()));
			}catch(IOException e2){
				System.out.println("Error Sengin no message attached to whisper");
			}
		} 
	}

	/****************************************
	 *Sends a list of all the clients connected
	 to the server to the client requesting it.

	 @param a client to send it to
	 * *************************************/
	private void sendClientList(Client c){
		try{
			out = new PrintWriter(c.getSocket().getOutputStream(), true);
			out.println(AES.encrypt("\nUSERS:", c.getAESkey()));
			//Sending each client at a time
			for(Client c2 : Server.clients){
				out.println(AES.encrypt(("	" + c2.getUserName()), c.getAESkey()));
			}
		}catch(IOException e){
			System.err.println("Error sending client list");
		}
	}

	/**********************************************
	 *Sends a message to all users connected to the
	 server

	 @param message to be broadcasted
	 * ******************************************/
	private void broadcastMessage(String message){
		try{
		//Sending message to each client in the clients vector
		for(Client c : Server.clients){
			out =  new PrintWriter(c.getSocket().getOutputStream(), true);
			out.println(AES.encrypt(message, c.getAESkey()));
		}
		}catch(IOException e){
			System.err.println("Error broadcasting a message to all clients");
		   }
	}
}

/*******************************************
 *This class is for creating client objects.
 each client will hold its socket, username,
 and AES key.
 * ***************************************/
class Client{
	private Socket socket;
	private String userName;
	private String AESkey;

	Client(Socket socket, String userName, String AESkey){
		this.socket = socket;
		this.userName = userName;
		this.AESkey = AESkey;
		Server.clients.addElement(this);
	}

	public Socket getSocket(){
		return socket;
	}

	public String getUserName(){
		return userName;
	}

	public String getAESkey(){
		return AESkey;
	}
}

/*****************************************
 *Runs AES algorithms

source: https://howtodoinjava.com/security/java-aes-encryption-example/
 * **************************************/
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

