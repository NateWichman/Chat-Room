import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.Vector;
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

	public static void main(String args[]){
		/**to hold all connected clients**/
	//	Vector<Client> clients = new Vector<Client>();

		/**Socket for the Server**/
		ServerSocket serverSocket = null;

		/**Port number for socket connection**/
		int portNumber;

		//Setting port number
		portNumber = 9876;
		
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
			new ClientThread(clientSocket).start();
		}
	}
}

class ClientThread extends Thread{
	private Client client;
	private Socket clientSocket;
	private PrintWriter out;
	BufferedReader in;

	ClientThread(Socket clientSocket){
		this.clientSocket = clientSocket;
		try{
			out = new PrintWriter(clientSocket.getOutputStream(),true);
			in = new BufferedReader(
					new InputStreamReader(clientSocket.getInputStream()));
		}catch(IOException e){
			System.err.println("Error creating new client");
		}
	}

	@Override
	public void run(){
		try{
			out.println("Enter a UserName: ");
			String userName = in.readLine(); 
			System.out.println(userName + " has joined");

			//Creating a client object, also adds client to static clients vector in this class (in constructor)
			 client = new Client(clientSocket, userName);

			String receivedMessage;

			//Receiving messages from the Client
			while((receivedMessage = in.readLine()) != null){
				System.out.println(client.getUserName() + ": " + receivedMessage);
				
				if(receivedMessage.equals("Exit")){
					System.out.println(client.getUserName() + " has dissconnected");
					break;
				}else if(receivedMessage.startsWith("/whisper")){
					System.out.println(userName + " is trying to whisper");
					whisperMessage(receivedMessage);
				}else{
					broadcastMessage("\n" + client.getUserName() + ": " + receivedMessage);
				}
			}

			in.close();
			out.close();
			Server.clients.removeElement(client);

			
		}catch(IOException e){
			System.err.println("ERROR handling client");
		}

	}

	private void whisperMessage(String message){
		try{
			int userNameStart = message.indexOf(" ");
			int userNameEnd = message.indexOf(" ", userNameStart + 1);
			System.out.println(userNameStart + "\n" + userNameEnd);
			String userName = message.substring(userNameStart + 1, userNameEnd);
			System.out.println("A message is being whipered to " + userName);

			boolean ClientFound = false;

			for(Client c : Server.clients){
				if(c.getUserName().equals(userName)){
					System.out.println("User Found");
					ClientFound = true;
					try{
						String cutMessage = message.substring(userNameEnd);
						out = new PrintWriter(c.getSocket().getOutputStream(),true);
						out.println("\n" + client.getUserName() + " is whispering to you: " + cutMessage);
					}catch(IOException e3){
						System.err.println("Error forwarding whisper");
					}
				}
			} 

			if(!ClientFound){
				System.out.println("Client Not Found");
			}
			
		}catch(IndexOutOfBoundsException e){
			System.err.println("No Message Attached to Whisper");
			try{
				out = new PrintWriter(client.getSocket().getOutputStream(),true);
				out.println("No Message Attached to Whisper");
			}catch(IOException e2){
				System.out.println("Error Sengin no message attached to whisper");
			}
		} 
	}

	private void broadcastMessage(String message){
		try{
		for(Client c : Server.clients){
			out =  new PrintWriter(c.getSocket().getOutputStream(), true);
			out.println(message);
		}
		}catch(IOException e){
			System.err.println("Error broadcasting a message to all clients");
		   }
	}
}

class Client{
	private Socket socket;
	private String userName;

	Client(Socket socket, String userName){
		this.socket = socket;
		this.userName = userName;
		Server.clients.addElement(this);
	}

	public Socket getSocket(){
		return socket;
	}

	public String getUserName(){
		return userName;
	}
}
