//Joshua Itagaki
//CS 380

package FileTransfer;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import javax.crypto.*;

public class FileTransfer {
	static Scanner kb = new Scanner(System.in);
	public static void main(String[] args) throws Exception{
		if(args[0].equalsIgnoreCase("makekeys")){
			makekey();
		}
		else if(args[0].equalsIgnoreCase("server") && args[1].equalsIgnoreCase("private.bin")){
			server(args[1],args[2]);
		}
		else if(args[0].equalsIgnoreCase("client") && args[1].equalsIgnoreCase("public.bin")){
			client(args[1], args[2], args[3]);
		}
		else{
			System.out.println("Not a valid input");
		}
	}

	private static void client(String keyFile, String host, String port) throws Exception{
		try(Socket socket = new Socket(host, Integer.parseInt(port))){
			System.out.println("Connected to server: " + Integer.parseInt(port));
			InputStream in = socket.getInputStream();
			OutputStream out = socket.getOutputStream();
			PublicKey publicKey = null;
			publicKey = getPublicKey(publicKey, keyFile);
			SecureRandom rand = new SecureRandom();
			KeyGenerator keyGen = KeyGenerator.getInstance("AES"); //Generate AES key
			keyGen.init(128, rand);
			Key wrapping = keyGen.generateKey();
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.WRAP_MODE, publicKey);	//Encrypt key
			byte[] wrapKey = cipher.wrap(wrapping);
			System.out.print("Enter path: ");
			String fileName = kb.nextLine();	//path to file
			File file = new File(fileName);
			FileInputStream inFile = null;
			byte[] bFile = new byte[(int) file.length()];
			inFile = new FileInputStream(file);
			inFile.read(bFile);
			System.out.print("Enter chunk size [1024]: ");
			int chunkS = kb.nextInt();
			int packet = calcPacket(chunkS, file.length());
			StartMessage startMess = new StartMessage(fileName, wrapKey, chunkS);
			ObjectInputStream ois = new ObjectInputStream(in);
			ObjectOutputStream oos = new ObjectOutputStream(out);
			oos.writeObject(startMess);
			cipher = Cipher.getInstance("AES");
			Chunk chunk = null;
			byte[] chunkD = null;
			int pointer = 0;
			System.out.print("Sending: " + fileName);
			System.out.println("	File Size: " + file.length());
			System.out.println("Sending " + packet + " chunks.");
			for(int i = 0; i < packet; i++){
				AckMessage ack = (AckMessage) ois.readObject();
				if(ack.getSeq() == i){
					System.out.println("Chunks completed [ " + ack.getSeq() + "/" + packet + "]");
					if((pointer + chunkS) < file.length()){
						chunkD = new byte[chunkS];
					}
					else {
						chunkD = new byte[(int) (file.length() - pointer)];
					}
					for(int j = 0; j < chunkS && ((j + pointer) < file.length()); j++){
						chunkD[j] = bFile[j + pointer];
					}
					Checksum cs = new CRC32();
					cs.update(chunkD, 0, chunkD.length);
					long crc = cs.getValue();
					cipher.init(Cipher.ENCRYPT_MODE, wrapping);
					byte[] decodeText = cipher.doFinal(chunkD);
					chunk = new Chunk(i, decodeText, (int) crc);
					oos.writeObject(chunk);
					pointer += chunkS;
				}
				else {
					i--;
					oos.writeObject(chunk);
				}
			}
			DisconnectMessage disconnect = new DisconnectMessage();
			oos.writeObject(disconnect);
		}
	}

	private static int calcPacket(int chunkS, long length) {
		int packets = (int) length / chunkS;
		double value = (double) length / (double) chunkS;
		if(value > (double) packets){
			packets++;
		}
		return packets;
	}

	private static PublicKey getPublicKey(PublicKey publicKey, String keyFile) 
			throws IOException, ClassNotFoundException {
		FileInputStream in = new FileInputStream(keyFile);
		ObjectInputStream oin = new ObjectInputStream(in);
		publicKey = (PublicKey) oin.readObject();
		return publicKey;
	}

	private static void server(String fileName, String port) throws Exception{
		try(ServerSocket serverSocket = new ServerSocket(Integer.parseInt(port))){
			while(true){
				Socket socket = serverSocket.accept();
				Thread thread = new Thread(new Runnable(){
					public void run() {
						try{
						String address = socket.getInetAddress().getHostAddress();
						InputStream in = socket.getInputStream();
						OutputStream out = socket.getOutputStream();
						PrivateKey priKey = null;
						priKey = getPrivateKey(priKey, fileName);
						ObjectInputStream ois = new ObjectInputStream(in);
						ObjectOutputStream oos = new ObjectOutputStream(out);
						Object message = ois.readObject();
						StartMessage startMess = null;
						StopMessage stopMess;
						Chunk chunk;
						if(message instanceof DisconnectMessage){
							socket.close();
						}
						else{
							startMess = (StartMessage) message;
						}
						byte[] wrappedKey = startMess.getEncryptedKey();
						Cipher cipher = Cipher.getInstance("RSA");
						cipher.init(Cipher.UNWRAP_MODE, priKey);
						Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
						int ack = 0;
						AckMessage ackM = new AckMessage(ack);
						oos.writeObject(ackM);
						long fileS = startMess.getSize();
						int chunkS = startMess.getChunkSize();
						int packet = calcPacket(chunkS, fileS);
						byte[] fileNew = new byte[(int) fileS];
						cipher = Cipher.getInstance("AES");
						int pointer = 0;
						for(int i = 0; i < packet; i++){
							chunk = (Chunk) ois.readObject();
							if(chunk.getSeq() == 1){
								cipher.init(Cipher.DECRYPT_MODE, key);
								byte[] decodeText = cipher.doFinal(chunk.getData());
								Checksum cs = new CRC32();
								cs.update(decodeText, 0, decodeText.length);
								long crc = cs.getValue();
								if(crc == (long) chunk.getCrc()){
									for(int j = 0; j < decodeText.length; j++){
										fileNew[j + pointer] = decodeText[j];
									}
									pointer += decodeText.length;
									ackM = new AckMessage(i++);
									oos.writeObject(ackM);
									System.out.println("Chunk received [" + chunk.getSeq() + "/" 
											+ packet + "]");
									if(chunk.getSeq() == packet){
										System.out.println("Trasfer complete");
										System.out.print("Output path: ");
										String fileName = kb.next();
										FileOutputStream fout = new FileOutputStream(fileName);
										fout.write(fileNew);
										break;
									}
								}
								else {
									ackM = new AckMessage(i);
									oos.writeObject(ackM);
									i--;
								}
							}
							else {
								ackM = new AckMessage(i);
								oos.writeObject(ackM);
								i--;
							}
						}
						}
						catch(Exception e){
							System.out.println(e);
						}
					}
				});
			}
		}
	}
	
	private static PrivateKey getPrivateKey(PrivateKey priKey, String fileName) 
			throws IOException, ClassNotFoundException{
		FileInputStream in = new FileInputStream(fileName);
		ObjectInputStream oin = new ObjectInputStream(in);
		priKey = (PrivateKey) oin.readObject();
		return priKey;
	}

	private static void makekey() {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(4096); // you can use 2048 for faster key generation
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(
					new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace(System.err);
		}
	}
}
