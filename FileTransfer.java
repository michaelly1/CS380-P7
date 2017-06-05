//Michael Ly CS380

import javax.crypto.*;
import java.util.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.zip.CRC32;

public class FileTransfer {

    public static void main(String[] args) {
        Scanner kb = new Scanner(System.in);
        try {
            if (args[0].equals("makekeys")) {
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
            } else if (args[0].equals("server") && args.length == 3) {
                smode(args[1], args[2]);
            }
            else if(args[0].equals("server") && args.length == 1) // only server is passed in for command args
            {
                System.out.println("Incorrect command arguments for server");
            }
            else if (args[0].equals("client") && args.length == 4) {
                cmode(args[1], args[2], args[3]);
            }
            else if (args[0].equals("client") && args.length == 1) // only client is passed in for command args
            {
                System.out.println("Incorrect command arguments for client");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void smode(String prK, String port)
    {
        try {
            //Gets the private key in private.bin
            ObjectInputStream oiss = new ObjectInputStream(new FileInputStream(prK));
            PrivateKey pk = (PrivateKey) oiss.readObject();

            //Creates the server socket with given port
            ServerSocket ss = new ServerSocket(Integer.parseInt(port));
            Socket socket = ss.accept();

            //input output
            InputStream is = socket.getInputStream();
            ObjectInputStream clientm = new ObjectInputStream(is);

            OutputStream os = socket.getOutputStream();
            ObjectOutputStream serverm = new ObjectOutputStream(os);

            Message m;
            Key unwPK = null;
            int seqNum = 0;
            int numOfChunks = 0;
            String outfile = "";
            FileOutputStream fout = null;

            do {
                m = (Message) clientm.readObject();

                //Start
                if (m.getType() == MessageType.START) {
                    StartMessage clientSTART = (StartMessage) m;

                    Cipher c = Cipher.getInstance("RSA");
                    c.init(Cipher.UNWRAP_MODE, pk);
                    unwPK = c.unwrap(clientSTART.getEncryptedKey(), "AES", Cipher.SECRET_KEY);

                    //saves in [filename]2.txt
                    outfile = clientSTART.getFile()+"2.txt";
                    fout = new FileOutputStream(outfile);

                    //gets the total number of chunks
                    numOfChunks = getNumOfChunks(clientSTART.getSize(), clientSTART.getChunkSize());

                    serverm.writeObject(new AckMessage(0));

                }
                //Stop
                else if (m.getType() == MessageType.STOP) {
                    StopMessage clientSTOP = (StopMessage) m;
                    serverm.writeObject(new AckMessage(-1));

                }
                //Chunk
                else if (m.getType() == MessageType.CHUNK) {
                    Chunk ch = (Chunk) m;

                    if(ch.getSeq() == seqNum)
                    {
                        Cipher ci = Cipher.getInstance("AES");
                        ci.init(Cipher.DECRYPT_MODE, unwPK);

                        byte[] chunkdata = ci.doFinal(ch.getData());

                        CRC32 crc = new CRC32();
                        crc.reset();
                        crc.update(chunkdata);

                        if((int)crc.getValue() == ch.getCrc())
                        {
                            fout.write(chunkdata);
                            seqNum++;
                            serverm.writeObject(new AckMessage(seqNum));
                            System.out.println("Chunk received [" +seqNum+"/"+numOfChunks+"]." );

                            if(numOfChunks == seqNum){
                                System.out.println("Transfer complete.\nOutput path: " + outfile);
                                fout.close();
                                continue;
                            }
                        }
                    }
                }
                else {
                    System.out.println(m.getType());
                }
            }while(m.getType() != MessageType.DISCONNECT);

            //Disconnect
            if (m.getType() == MessageType.DISCONNECT) {
                ss.close();
                socket.close();
                System.exit(0);
            }
            clientm.close();
            serverm.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    public static void cmode(String puK, String host, String port)
    {
        try {
            Scanner kb = new Scanner(System.in);

            //Gets the public key
            ObjectInputStream oisc = new ObjectInputStream(new FileInputStream(puK));
            PublicKey puk = (PublicKey) oisc.readObject();

            //Socket to host and port
            Socket socket = new Socket(host, Integer.parseInt(port));

            if(socket.isConnected()) {
                System.out.println("Connected to server: " + host + "/" + socket.getInetAddress().getHostAddress());
            }
            else
            {
                System.out.println("Wrong host or port");
                System.exit(1);
            }

            //input output
            InputStream is = socket.getInputStream();
            ObjectInputStream serverob = new ObjectInputStream(is);

            OutputStream os = socket.getOutputStream();
            ObjectOutputStream clientob = new ObjectOutputStream(os);

            //key generator
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            //could be 128 or 192 as well?
            keygen.init(256);
            Key sessionkey = keygen.generateKey();

            Cipher en = Cipher.getInstance("RSA");
            en.init(Cipher.WRAP_MODE, puk);
            byte[] enSessionK = en.wrap(sessionkey);

            System.out.println("Enter path: ");
            String fout = kb.nextLine();
            File file = new File(fout+".txt");

            if(!file.exists())
            {
                System.out.println("File doesn't exist");
                System.exit(1);
            }

            //default chunk size is 1024
            System.out.println("Enter chunk size [1024]: ");
            int cSize = kb.nextInt();
            kb.nextLine();

            byte[] fileData;
            FileInputStream fin = new FileInputStream(fout + ".txt");

            //Start message
            clientob.writeObject(new StartMessage(fout+".txt",enSessionK,cSize));

            Message m = (Message) serverob.readObject();

            if(((AckMessage)m).getSeq() != 0)
            {
                System.out.println("Error");
                System.exit(1);
            }

            int numofCh = getNumOfChunks(file.length(), cSize);
            System.out.println("Sending: " + fout + ".txt.\tFile size: " + file.length()+".\nSending "+numofCh+" chunks.");

            //Transfer
            for(int i = 0; i < numofCh; i++)
            {
                if(((AckMessage)m).getSeq() == i)
                {
                    fileData = new byte[cSize];
                    fin.read(fileData);

                    en = Cipher.getInstance("AES");
                    en.init(Cipher.ENCRYPT_MODE, sessionkey);
                    byte[] enFileData = en.doFinal(fileData);

                    CRC32 crc = new CRC32();
                    crc.reset();
                    crc.update(fileData);

                    clientob.writeObject(new Chunk(((AckMessage)m).getSeq(), enFileData, (int)crc.getValue()));

                    System.out.println("Chunks completed [" + (i+1) + "/"+numofCh+"].");
                    m = (Message) serverob.readObject();
                }
            }

            clientob.writeObject(new DisconnectMessage());
            socket.close();

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    //if file size has some leftovers due to chunk size splitting it up
    public static int getNumOfChunks(long s, int cs)
    {
        int temp = (int) s/cs;
        if(temp < (double) s/cs )
        {
            return temp++;
        }
        return temp;
    }
}
