/**
 * CS 1699 Project 1: StringCoin
 * Fall 2018
 * Author: Michael Korst (mpk44@pitt.edu)
 */

 import java.io.*;
 import java.security.*;
 import java.security.spec.*;
 import java.util.*;
 import java.lang.StringBuilder;
 import java.nio.charset.StandardCharsets;

 public class StringCoin
 {
   //hash map to track what address (public key) controls coin; Key: Coin, Value: Address
   static HashMap<String, String> coin_map = new HashMap<>();
   static int coin_count;           //number of coins in circulation
   //since Bill is originator of all coins, we require his public key
   static final String bill_pub = "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecb" +
   "cd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d" +
   "9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0d" +
   "a20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10";

   /**
    * Given some arbitrary byte array bytes, convert it to a hex string.
    * Example: [0xFF, 0xA0, 0x01] -> "FFA001"
    * Code borrowed from Laboon: Sha256Hash.java
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
    * Given a string toCheck, its signature, and a PUBLIC key pk, verifies
    * that the string was signed by the corresponding secret key sk to pk.
    * Code borrowed from Laboon: PublicKeyDemo.java
    * @param toCheck - string to check
    * @param sig - signature in byte array form
    * @parak pk - public key
    * @return boolean - true if valid, false otherwise
    */
  public static boolean verify(String toCheck, byte[] sig, PublicKey pk)
  throws Exception
  {
    Signature sig2 = Signature.getInstance("SHA1withDSA", "SUN");
    byte[] bytes = toCheck.getBytes();
    sig2.initVerify(pk);
    sig2.update(bytes, 0, bytes.length);
    return sig2.verify(sig);
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

   /**
    * Verify a hash provided by the file using the line in question to compare HashableObjects
    * Based on Laboon - HashPointer.java:calculateHash
    * @param block_line - line of blockchain to check hash against
    * @param block_hash - hash of that line (provided in file) to compare
    * @return Boolean - true if hash valid, false if not (throws exception)
   */
   public static boolean validate_hash(String block_line, String block_hash) throws InvalidDataException
   {
     if (block_line == null && block_hash.equals("0"))
     {
       return true;         //genesis block, special hash
     }
     //remove new lines and tabs
     block_line = block_line.replaceAll("\\r\\n", "");
     byte[] hash = null;
     byte[] file_hash = convertHexToBytes(block_hash);

     try
     {
       //create SHA-256 hash of raw line to ensure following hash is correct
       MessageDigest md = MessageDigest.getInstance("SHA-256");
       md.update(block_line.getBytes());
       hash = md.digest();
     } catch (NoSuchAlgorithmException nsaex)
     {
       System.err.println("No SHA-256 algorithm found.");
 	     System.err.println("This generally should not happen...");
 	     System.exit(1);
     }
     //check if the hash in the file was valid for the line in question
     if (Arrays.equals(hash, file_hash))
     {
       return true;         //file hash is valid
     } else
     {
       throw new InvalidDataException(block_hash, 0);
     }
   }

   /**
    * Verify a create coin transaction, create if valid
    * @param coin_id - coin in question to create
    * @param coin_sig - name of coin signed with Bill's secret key
    * @return Boolean - true if coin validly created and tracked, false if not (throws exception)
   */
   public static boolean create_coin(String coin_id, String coin_sig) throws Exception
   {
     //coin already exists, invalid
     if (coin_map.containsKey(coin_id))
     {
       throw new InvalidDataException(coin_id, 1);
     }
     boolean valid_coin_sig;
     //see if coin validly signed by Bill
     valid_coin_sig = verifyMessage(coin_id, coin_sig, bill_pub);
     if (!valid_coin_sig)
     {
       //invalidly signed coins
       throw new InvalidDataException(coin_sig, 3);
     } else {
       //coin validly created, associate coin with Bill's pub key as he is creator, increment count
       coin_count++;
       coin_map.put(coin_id, bill_pub);
       return true;
     }
   }

   /**
    * Helper method to build String to check block_sig against for each line
    * @param block_line - line to format for use in sig verification
    * @return String - formatted String that will verify against block_sig
   */
   public static String get_partial(String block_line)
   {
     //take apart line then add back in necessary
     String[] block_args = block_line.split(",");
     StringBuilder sb = new StringBuilder();
     for (int i = 0; i < 4; i++)
     {
       //adds each param back, adds comma EXCEPT final comma
       sb.append(block_args[i]);
       if (i < 3) sb.append(",");
     }
     return sb.toString();
   }

   /**
    * Verify the signature of a block for a block for whoever coin owner is
    * @param partial_block - Portion of block being signed by block_sig
    * @param block_sig - Signature provided of block in file
    * @param coin_id - ID of coin for block, used to check who owner is
    * @return Boolean - true if block validly signed, false otherwise (throws exception)
   */
   public static boolean check_sig(String partial_block, String block_sig, String coin_id)
   throws Exception
   {
     boolean valid_sig;
     String block_pk = coin_map.get(coin_id);
     if (block_pk == null)
     {
       throw new InvalidDataException(coin_id, 1);
     }
     valid_sig = verifyMessage(partial_block, block_sig, block_pk);
     if (!valid_sig)
     {
       throw new InvalidDataException(block_sig, 2);
     } else {
       return true;         //fine
     }
   }

   /**
    * Verify a transfer coin operation, transfer if valid
    * @param coin_id - coin in question to transfer
    * @param recip_key - public key (address) of recipient of coin
    * @return Boolean - true if coin valid and transferred, false if invalid
   */
   public static boolean transfer_coin(String coin_id, String recip_key) throws InvalidDataException
   {
     //coin doesn't exist, invalid
     if (!coin_map.containsKey(coin_id))
     {
       throw new InvalidDataException(coin_id, 1);
     }
     //valid coin! transfer
     coin_map.put(coin_id, recip_key);
     return true;
   }

   public static void main(String[] args) throws Exception
   {
     BufferedReader br;
     int lines = 0;
     List<String[]> trans_list = new ArrayList<String[]>();      //records each block parameter, removing commas
     List<String> line_list = new ArrayList<String>();           //records each raw line
     String line;                 //records each line
     try
     {
       //create reader to read from blockchain file
       br = new BufferedReader(new FileReader(args[0]));
       line = br.readLine();
       while (line != null)         //count lines in file
       {
         lines++;
         line = br.readLine();
       }
       br.close();        //close file for now
     } catch (IOException e)
     {
       System.err.println(e);
       System.exit(1);        //something wrong with input file, exit
     }

     try
     {
       br = new BufferedReader(new FileReader(args[0]));    //open file again
       //special case for genesis block
       line = br.readLine();
       try
       {
         trans_list.add(line.split(","));
         line_list.add(line);
         if (!(trans_list.get(0)[0]).equals("0"))
         {
           throw new InvalidDataException((trans_list.get(0)[0]), 4);
         }
       } catch (InvalidDataException ide)
       {
         System.err.println("InvalidDataException: " + ide);
         ide.printStackTrace();
         System.err.println("Quitting...");
         System.exit(1);
       }

       //first, read through file and add each transaction parameter line to List
       for (int i = 1; i < lines; i++)
       {
         line = br.readLine();
         line_list.add(line);
         trans_list.add(line.split(","));
       }
     } catch (IOException e)
     {
       System.err.println(e);
       System.exit(1);        //something wrong with input file, exit
     }

     //now validate each block
     //genesis block special case, no hash to check, so start checking hashes at index 1
     //now, go through each block, either creating or transferring contains
     //continue to validate signatures for both coin (if necessary) and line
     //int j = 0;
     boolean valid_ret;
     String check_block;      //string we will use to validate block_sig
     for (int j = 0; j < lines; j++)
     {
       //checks if not end of file, checks hash if not
       if (j < (lines -1))
       {
         valid_ret = validate_hash(line_list.get(j), (trans_list.get(j+1)[0]));
         if (!valid_ret)
         {
           System.exit(1);          //input error, exiting
         }
       }
       check_block = get_partial(line_list.get(j));     //partial to check against block_sig
       try
       {
         if ((trans_list.get(j)[1]).equals("CREATE"))
         {
           //CREATE block, try creating coin
           valid_ret = create_coin((trans_list.get(j)[2]), (trans_list.get(j)[3]));
           if (!valid_ret)
           {
             System.exit(1);        //input error, exiting...
           }
           //now see if valid signature for Bill (creator)
           valid_ret = check_sig(check_block, (trans_list.get(j)[4]), (trans_list.get(j)[2]));
           if (!valid_ret)
           {
             System.exit(1);        //input error, exiting...
           }
         } else if ((trans_list.get(j)[1]).equals("TRANSFER"))
         {
           //TRANSFER block, validate sig first, then transfer if ok
           valid_ret = check_sig(check_block, (trans_list.get(j)[4]), (trans_list.get(j)[2]));
           if (!valid_ret)
           {
             System.exit(1);        //input error, exiting...
           }
           valid_ret = transfer_coin((trans_list.get(j)[2]), (trans_list.get(j)[3]));
           if (!valid_ret)
           {
             System.exit(1);        //input error, exiting...
           }
         } else
         {
           throw new InvalidDataException((trans_list.get(j)[1]), 5);
         }
       } catch (InvalidDataException ide)
       {
         System.err.println("InvalidDataException: " + ide);
         ide.printStackTrace();
         System.err.println("Quitting...");
         System.exit(1);
       }

       //j++;  //continue through the lines
     }
     //create sorted set of coins for printing
     Set <String> sort_coins = new TreeSet<>(coin_map.keySet());
     for (String coin : sort_coins)
     {
       System.out.println("Coin " + coin + " / Owner = " + coin_map.get(coin));
     }
     System.exit(0);              //successful completion!
   }
}
