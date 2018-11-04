import java.io.*;
import java.net.Socket;
import java.util.Scanner;

public class ClientClass{

    public static void main(String[] args) throws IOExcpetion{
	String serverHostname;
	int portNumber;
	Scanner scn = new Scanner(System.in);

	try{
	    System.out.print("IP address: ");
	    serverHostname = scn.next();
	    System.out.print("\nPort number: ");
	    portNumber = Integer.parseInt(scn.next());
	    System.out.print("\n");

	    System.out.println ("Attemping to connect to host " +
				serverHostname + " on port " + portNumber);

	    Socket socket = null;
	    PrintWriter out = null;
	    BufferedReader in = null;
	    socket = new Socket(serverHostname, portNumber);
	    out = new PrintWriter(socket.getOutputStream(), true);
	    in = new BufferedReader(new InputStreamReader(
							  socket.getInputStream()));

	    BufferedReader stdIn = new BufferedReader(
						      new InputStreamReader(System.in));
	     String userInput;

	    new receiveThread2(socket).start();

	    System.out.println("Input: ");
	    while ((userInput = stdIn.readLine()) != null) {
		out.println(userInput);
		System.out.print ("Input: ");
		if(userInput.equals("Exit")){
		    break;
		}
		} 

	    out.close();
	    in.close();
	    stdIn.close();
	}catch(IOException e){
	    System.out.println("ERROR");
	}
    }    
}


class receiveThread2 extends Thread{
	Socket socket;

	receiveThread2(Socket socket){
		this.socket = socket;
	}

	public void run(){
		try{
		BufferedReader in = new BufferedReader(
						new InputStreamReader(socket.getInputStream()));

		String inputLine;

		while((inputLine = in.readLine()) != null){
			System.out.println(inputLine);

			if(inputLine.equals("Exit")){
				System.exit(0);
				break;
			}
		}

		in.close();
		socket.close();
		}catch(IOException e){
			System.out.println("Error Receiving Message");
		}

	}
}


