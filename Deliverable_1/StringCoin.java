/**
 * Implementation of centralized StringCoin cryptocurrency
 */

 import java.io.*;
 import java.security.*;
 import java.security.spec.*;

 public class StringCoin
 {

   /**
    * Given some arbitrary byte array bytes, convert it to a hex string.
    * Example: [0xFF, 0xA0, 0x01] -> "FFA001"
    * @param bytes arbitrary-length array of bytes
    * @return String hex string version of byte array
    */

   public static String convertBytesToHexString(byte[] bytes)
   {
     StringBuffer toReturn = new StringBuffer();
     for (int j = 0; j < bytes.length; j++) {
       String hexit = String.format("%02x", bytes[j]);
       toReturn.append(hexit);
     }
     return toReturn.toString();
   }


   /**
    * Given some arbitrary hex string, convert it to a byte array.
    * Example: "FFA001" -> [0xFF, 0xA0, 0x01]
    * NOTE: Assumes that hex string is valid (i.e., even length)
    * Code borrowed from Laboon: PublicKeyDemo.java
    * @param hex arbitrary-length hex string
    * @return byte[] byte array version of hex string
    */

   public static byte[] convertHexToBytes(String hex)
   {
     byte[] bytes = new byte[hex.length() / 2];
     int c = 0;
     for (int j = 0; j < hex.length(); j += 2) {
       String twoHex = hex.substring(j, j + 2);
       byte byteVal = (byte) Integer.parseInt(twoHex, 16);
       bytes[c++] = byteVal;
     }
     return bytes;
   }

   /**
    * Generate a public key in bytes given a hex string.
    * We can then store hex strings as our public key instead of raw bytes.
    * Code borrowed from Laboon: PublicKeyDemo.java
    * @param stored - Public key in hex
    * @return PublicKey - a usable PublicKey object
    */

   public static PublicKey loadPublicKey(String stored) throws Exception
   {
     byte[] data = convertHexToBytes(stored);
     X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
     KeyFactory fact = KeyFactory.getInstance("DSA");
     return fact.generatePublic(spec);
   }
   /**
    * Verify a message using a String version of the msg, signature and key.
    * Will be useful for command-line tools!
    * Code borrowed from Laboon: PublicKeyDemo.java
    * @param msg - The message
    * @param sig - The signature (hex string)
    * @param key - The public key of the original signer (hex string)
    * @return Boolean - true if valid, false if not
    */

   public static boolean verifyMessage(String msg, String sig, String key) throws Exception
   {
     PublicKey pk = loadPublicKey(key);
     byte[] sigBytes = convertHexToBytes(sig);
     boolean toReturn = verify(msg, sigBytes, pk);
     return toReturn;
   }


   public static void main(String[] args)
   {
     BufferedReader br;
     int lines = 0;
     List<String> trans_list = new List<String>();
     try
     {
       //create reader to read from blockchain file
       br = new BufferedReader(new FileReader(args[0]));
       String line = br.readLine();
       while (line != null)         //count lines in file
       {
         lines++;
         line = br.readLine();
       }
     } catch (IOException e)
     {
       System.err.println(e);
       System.exit(1);        //something wrong with input file, exit
     }
     br.close();        //close file for now
     //now that we have number of lines (num of blocks), we can build blockchain
     Blockchain blockchain = new Blockchain();
     Block[] blocks = new Block[lines];
     br = new BufferedReader(new FileReader(args[0]));    //open file again
     String curr_line;

     //first, read through file and add each transaction parameter to List
     for (int i = 0; i < lines; i++)
     {
       curr_line = br.readLine();
       trans_list.addAll(Arrays.asList(curr_line.split(",")));
     }
   }
}
