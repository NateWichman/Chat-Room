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
	private void kickUser(String message){
		try{
			out = new PrintWriter(client.getSocket().getOutputStream(), true);
			BufferedReader tempIn = new BufferedReader(
					new InputStreamReader(client.getSocket().getInputStream()));
			String userName = "";
			try{
				int userNameStart = message.indexOf(" ");
				int userNameEnd = message.indexOf(" ", userNameStart + 1);
				userName = message.substring(userNameStart + 1, userNameEnd);
			}catch(IndexOutOfBoundsException e){
				out.println("Incorrect kick format, use /kick username");
				return;
			}
			System.out.println("Recieved Correct kick command");
			String input;
			out.println("\nEnter Admin Password: ");
			input = tempIn.readLine();
			if(input.equals(Server.adminPassword)){
				System.out.println("Correct Admin Password");
			}else{
				out.println("\nPASSWORD WAS NOT CORRECT");
			}
			boolean clientKicked = false;
			for(Client c : Server.clients){
				if(c.getUserName().equals(userName)){
					PrintWriter tempOut = new PrintWriter(c.getSocket().getOutputStream(), true);
					tempOut.println("\nYou have been kicked from the server by an admin");
					tempOut.println("Exit");
					Server.clients.removeElement(c);
					clientKicked = true;
					broadcastMessage(userName + " has been kicked from the server");
				}
			}
			if(!clientKicked){
				out.println("No User found by that name to kick from server");
			}
		}catch(IOException e3){
			System.err.println("Error in method: kickUser");
		}
	}
	private void whisperMessage(String message){
		try{
			int userNameStart = message.indexOf(" ");
			int userNameEnd = message.indexOf(" ", userNameStart + 1);
			String userName = message.substring(userNameStart + 1, userNameEnd);
			System.out.println("A message is being whipered to " + userName);

			boolean ClientFound = false;

			for(Client c : Server.clients){
				if(c.getUserName().equals(userName)){
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
				try{
					out = new PrintWriter(client.getSocket().getOutputStream(), true);
					out.println("\nNo user found by the username: " + userName);
				}catch(IOException e4){
					System.err.println("Error sending no user found for whisper functionality");
				}
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

	private void sendClientList(Client c){
		try{
			out = new PrintWriter(c.getSocket().getOutputStream(), true);
			out.println("");
			for(Client c2 : Server.clients){
				out.println(c2.getUserName());
			}
		}catch(IOException e){
			System.err.println("Error sending client list");
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
