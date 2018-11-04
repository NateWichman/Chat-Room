import java.io.*;
import java.net.Socket;
import java.util.Scanner;


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

			System.out.print(in.readLine());
			out.println(stdIn.readLine());

			new inputThread(socket).start();

			System.out.print("\nYou have been accepted to the server\nYou may begin sending messages\n");
			while((userInput = stdIn.readLine()) != null){
				out.println(userInput);

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
}

class inputThread extends Thread{
	Socket socket;

	inputThread(Socket socket){
		this.socket = socket;
	}

	@Override
	public void run(){
		try{
			BufferedReader in = new BufferedReader(
					new InputStreamReader(socket.getInputStream()));
			String inputLine;

			while((inputLine = in.readLine()) != null){
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
